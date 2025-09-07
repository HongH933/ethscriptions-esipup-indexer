class Token < ApplicationRecord
  include FacetRailsCommon::OrderQuery

  initialize_order_query({
    newest_first: [
      [:deploy_block_number, :desc],
      [:deploy_transaction_index, :desc, unique: true]
    ],
    oldest_first: [
      [:deploy_block_number, :asc],
      [:deploy_transaction_index, :asc, unique: true]
    ]
  }, page_key_attributes: [:deploy_ethscription_transaction_hash])
    
  has_many :token_items,
    foreign_key: :deploy_ethscription_transaction_hash,
    primary_key: :deploy_ethscription_transaction_hash,
    inverse_of: :token
    
  belongs_to :deploy_ethscription,
    foreign_key: :deploy_ethscription_transaction_hash,
    primary_key: :transaction_hash,
    class_name: 'Ethscription',
    inverse_of: :token,
    optional: true
  
  has_many :token_states, foreign_key: :deploy_ethscription_transaction_hash, primary_key: :deploy_ethscription_transaction_hash, inverse_of: :token

  scope :minted_out, -> { where("total_supply = max_supply") }
  scope :not_minted_out, -> { where("total_supply < max_supply") }

    # === ESIP-UP: normalize & validations ===
  before_validation :normalize_toadd

  validates :premint, numericality: { greater_than_or_equal_to: 0 }, if: :up_mode?
  validate  :validate_up_mode_fields

  private

  def normalize_toadd
    self.toadd = toadd&.downcase
  end

  # 仅当 up_mode 开启时才检查/Only checked if up_mode is on
  def validate_up_mode_fields
    return unless up_mode?

    if toadd.blank?
      errors.add(:toadd, "must be present when up_mode is true")
    elsif !toadd.match?(/\A0x[0-9a-f]{40}\z/) # 统一小写十六进制地址/lowercase hexadecimal addresses
      errors.add(:toadd, "must be a valid lowercase hex address (0x...)")
    end

    if premint.to_i > max_supply.to_i
      errors.add(:premint, "cannot exceed max_supply")
    end

    # 可选：整除性校验，避免尾数（如果不需要，可整段注释掉）
    if mint_amount.to_i > 0
      if (premint.to_i % mint_amount.to_i) != 0
        errors.add(:premint, "must be divisible by mint_amount")
      end
      if ((max_supply.to_i - premint.to_i) % mint_amount.to_i) != 0
        errors.add(:base, "public cap must be divisible by mint_amount")
      end
    end
  end

  
  def minted_out?
    total_supply == max_supply
  end

    # === ESIP-UP: helpers ===
  def up_mode?
    # 如果 DB 有 boolean 列 up_mode，直接用；若没有，up_mode 默认为 false/If the DB has a boolean column up_mode, use it directly; if not, up_mode defaults to false
    super
  rescue NoMethodError
    false
  end

  def premint_cap
    premint.to_i
  end

  def public_cap
    max_supply.to_i - premint.to_i
  end

  def premint_remaining
    premint_cap - premint_minted.to_i
  end

  def public_remaining
    public_cap - public_minted.to_i
  end

  # tx_from 需要在“mint 处理点”处传进来（小写）
  def use_premint?(tx_from)
    up_mode? &&
      tx_from.to_s.downcase == toadd.to_s &&
      premint_minted.to_i < premint_cap
  end

  def can_mint_premint?(amt)
    premint_remaining >= amt.to_i
  end

  def can_mint_public?(amt)
    public_remaining >= amt.to_i
  end

  # 实际累加水位（注意：这里只更新自身字段，不写 balances；balances 仍按官方口径在处理器里更新）
  #Actual accumulated level (Note: only the fields themselves are updated here, not balances; balances are still updated in the processor according to official specifications)
  def apply_premint!(amt)
    a = amt.to_i
    self.premint_minted = premint_minted.to_i + a
    self.total_supply   = total_supply.to_i   + a
  end

  def apply_public!(amt)
    a = amt.to_i
    self.public_minted  = public_minted.to_i + a
    self.total_supply   = total_supply.to_i   + a
  end

  
  def self.create_from_token_details!(tick:, p:, max:, lim:)
    deploy_tx = find_deploy_transaction(tick: tick, p: p, max: max, lim: lim)
    
    existing = find_by(deploy_ethscription_transaction_hash: deploy_tx.transaction_hash)
    
    return existing if existing
    
    content = OpenStruct.new(JSON.parse(deploy_tx.content))
    
    token = nil
    
    Token.transaction do
      token = create!(
        deploy_ethscription_transaction_hash: deploy_tx.transaction_hash,
        deploy_block_number: deploy_tx.block_number,
        deploy_transaction_index: deploy_tx.transaction_index,
        protocol: content.p,
        tick: content.tick,
        max_supply: content.max.to_i,
        mint_amount: content.lim.to_i,
        total_supply: 0
      )
      
      token.sync_past_token_items!
      token.save_state_checkpoint!
    end
    
    token
  end
  
  def self.process_block(block)
    all_tokens = Token.all.to_a
    
    return unless all_tokens.present?
    
    transfers = EthscriptionTransfer.where(block_number: block.block_number).includes(:ethscription)

    transfers_by_token = transfers.group_by do |transfer|
      all_tokens.detect { |token| token.ethscription_is_token_item?(transfer.ethscription) }
    end
    
    new_token_items = []
    
    # Process each token's transfers as a batch
    transfers_by_token.each do |token, transfers|
      next unless token.present?

      # Start with the current state
      total_supply = token.total_supply.to_i
      balances = Hash.new(0).merge(token.balances.deep_dup)

      # Apply all transfers to the state
      transfers.each do |transfer|
        balances[transfer.to_address] += token.mint_amount
        
        if transfer.is_only_transfer?
          total_supply += token.mint_amount
          # Prepare token item for bulk import
          new_token_items << TokenItem.new(
            deploy_ethscription_transaction_hash: token.deploy_ethscription_transaction_hash,
            ethscription_transaction_hash: transfer.ethscription_transaction_hash,
            token_item_id: token.token_id_from_ethscription(transfer.ethscription),
            block_number: transfer.block_number,
            transaction_index: transfer.transaction_index
          )
        else
          balances[transfer.from_address] -= token.mint_amount
        end
      end

      balances.delete_if { |address, amount| amount == 0 }
      
      if balances.values.any?(&:negative?)
        raise "Negative balance detected in block: #{block.block_number}"
      end
      
      # Create a single state change for the block
      token.token_states.create!(
        total_supply: total_supply,
        balances: balances,
        block_number: block.block_number,
        block_timestamp: block.timestamp,
        block_blockhash: block.blockhash,
      )
    end
    
    TokenItem.import!(new_token_items) if new_token_items.present?
  end
  
  def token_id_from_ethscription(ethscription)
    regex = /\Adata:,\{"p":"#{Regexp.escape(protocol)}","op":"mint","tick":"#{Regexp.escape(tick)}","id":"([1-9][0-9]{0,#{trailing_digit_count}})","amt":"#{mint_amount.to_i}"\}\z/
    
    id = ethscription.content_uri[regex, 1]
    
    id_valid = id.to_i.between?(1, max_id)
    
    creation_sequence_valid = ethscription.block_number > deploy_block_number ||
    (ethscription.block_number == deploy_block_number &&
    ethscription.transaction_index > deploy_transaction_index)
    
    (id_valid && creation_sequence_valid) ? id.to_i : nil
  end
  
  def ethscription_is_token_item?(ethscription)
    token_id_from_ethscription(ethscription).present?
  end
  
  def trailing_digit_count
    max_id.to_i.to_s.length - 1
  end
  
  def sync_past_token_items!
    return if minted_out?
    
    unless tick =~ /\A[[:alnum:]\p{Emoji_Presentation}]+\z/
      raise "Invalid tick format: #{tick.inspect}"
    end
    quoted_tick = ActiveRecord::Base.connection.quote_string(tick)
    
    unless protocol =~ /\A[a-z0-9\-]+\z/
      raise "Invalid protocol format: #{protocol.inspect}"
    end
    quoted_protocol = ActiveRecord::Base.connection.quote_string(protocol)

    regex = %Q{^data:,{"p":"#{quoted_protocol}","op":"mint","tick":"#{quoted_tick}","id":"([1-9][0-9]{0,#{trailing_digit_count}})","amt":"#{mint_amount.to_i}"}$}

    deploy_ethscription = Ethscription.find_by(
      transaction_hash: deploy_ethscription_transaction_hash
    )
    
    sql = <<-SQL
      INSERT INTO token_items (
        ethscription_transaction_hash,
        deploy_ethscription_transaction_hash,
        token_item_id,
        block_number,
        transaction_index,
        created_at,
        updated_at
      )
      SELECT 
        e.transaction_hash,
        '#{deploy_ethscription_transaction_hash}',
        (substring(e.content_uri from '#{regex}')::integer),
        e.block_number,
        e.transaction_index,
        NOW(),
        NOW()
      FROM 
        ethscriptions e
      WHERE 
        e.content_uri ~ '#{regex}' AND
        substring(e.content_uri from '#{regex}')::integer BETWEEN 1 AND #{max_id} AND
        (
          e.block_number > #{deploy_ethscription.block_number} OR 
          (
            e.block_number = #{deploy_ethscription.block_number} AND 
            e.transaction_index > #{deploy_ethscription.transaction_index}
          )
        )
      ON CONFLICT (ethscription_transaction_hash, deploy_ethscription_transaction_hash, token_item_id) 
      DO NOTHING
    SQL

    ActiveRecord::Base.connection.execute(sql)
  end
  
  def max_id
    max_supply.div(mint_amount)
  end
  
  def token_items_checksum
    Rails.cache.fetch(["token-items-checksum", token_items]) do
      item_hashes = token_items.select(:ethscription_transaction_hash)
      scope = Ethscription.oldest_first.where(transaction_hash: item_hashes)
      Ethscription.scope_checksum(scope)
    end
  end
  
  def balance_of(address)
    balances.fetch(address&.downcase, 0)
  end
  
  def save_state_checkpoint!
    item_hashes = token_items.select(:ethscription_transaction_hash)
    
    last_transfer = EthscriptionTransfer.
      where(ethscription_transaction_hash: item_hashes).
      newest_first.first
    
    return unless last_transfer.present?
      
    balances = Ethscription.where(transaction_hash: item_hashes).
      select(
        :current_owner,
        Arel.sql("SUM(#{mint_amount}) AS balance"),
        Arel.sql("(SELECT block_number FROM eth_blocks WHERE imported_at IS NOT NULL ORDER BY block_number DESC LIMIT 1) AS latest_block_number"),
        Arel.sql("(SELECT blockhash FROM eth_blocks WHERE imported_at IS NOT NULL ORDER BY block_number DESC LIMIT 1) AS latest_block_hash")
      ).
      group(:current_owner)

    balance_map = balances.each_with_object({}) do |balance, map|
      map[balance.current_owner] = balance.balance
    end

    latest_block_number = balances.first&.latest_block_number
    latest_block_hash = balances.first&.latest_block_hash
    
    if latest_block_number > last_transfer.block_number
      token_states.create!(
        total_supply: balance_map.values.sum,
        balances: balance_map,
        block_number: latest_block_number,
        block_blockhash: latest_block_hash,
        block_timestamp: EthBlock.where(block_number: latest_block_number).pick(:timestamp),
      )
    end
  end
  
  def self.batch_import(tokens)
    tokens.each do |token|
      tick = token.fetch('tick')
      protocol = token.fetch('p')
      max = token.fetch('max')
      lim = token.fetch('lim')
      
      create_from_token_details!(tick: tick, p: protocol, max: max, lim: lim)
    end
  end
  
  def self.find_deploy_transaction(tick:, p:, max:, lim:)    
    uri = %<data:,{"p":"#{p}","op":"deploy","tick":"#{tick}","max":"#{max}","lim":"#{lim}"}>
    
    Ethscription.find_by_content_uri(uri)
  end
  
  def as_json(options = {})
    super(options.merge(except: [
      :balances,
      :id,
      :created_at,
      :updated_at
    ])).tap do |json|
      if options[:include_balances]
        json[:balances] = balances
      end

      # === ESIP-UP: expose extra fields when enabled ===
      if up_mode?
        json[:up_mode]        = true
        json[:premint]        = premint
        json[:toadd]          = toadd
        json[:premint_minted] = premint_minted
        json[:public_minted]  = public_minted
        # total_supply Already in existing field
      end
    end
  end
end
