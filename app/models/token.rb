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

  public
  
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

      # === 1) 以 tokens 表里的状态为起点；把已有 balances 的“地址键”统一成小写 ===
      total_supply = token.total_supply.to_i
      existing     = (token.balances || {}).dup
      balances     = Hash.new(0)
      existing.each { |addr, amt| balances[addr.to_s.downcase] += amt.to_i }

      # === 2) 应用本块 transfers（同区块内按 tx index 排序，确保顺序一致） ===
      transfers = transfers.sort_by(&:transaction_index)

      transfers.each do |transfer|
        to_addr   = transfer.to_address.to_s.downcase
        from_addr = transfer.from_address.to_s.downcase

        if transfer.is_only_transfer?
          # —— 铸造（首次转移）
          mint_accepted = true

          if token.up_mode?
            if token.use_premint?(from_addr)
              unless token.can_mint_premint?(token.mint_amount)
                mint_accepted = false
              else
                token.apply_premint!(token.mint_amount)
              end
            else
              unless token.can_mint_public?(token.mint_amount)
                mint_accepted = false
              else
                token.apply_public!(token.mint_amount)
              end
            end
          else
            # 非 up_mode：保持官方行为（直接接受）
            token.total_supply = token.total_supply.to_i + token.mint_amount
          end

          if mint_accepted
            balances[to_addr] += token.mint_amount
            total_supply      += token.mint_amount

            new_token_items << TokenItem.new(
              deploy_ethscription_transaction_hash: token.deploy_ethscription_transaction_hash,
              ethscription_transaction_hash: transfer.ethscription_transaction_hash,
              token_item_id: token.token_id_from_ethscription(transfer.ethscription),
              block_number: transfer.block_number,
              transaction_index: transfer.transaction_index
            )
          end
        else
          # —— 普通转移（非铸造）
          balances[to_addr]   += token.mint_amount
          balances[from_addr] -= token.mint_amount
        end
      end

      balances.delete_if { |_, amount| amount == 0 }
      if balances.values.any?(&:negative?)
        raise "Negative balance detected in block: #{block.block_number}"
      end

      # === 3) 记“本块快照” ===
      token.token_states.create!(
        total_supply:   total_supply,
        balances:       balances,
        block_number:   block.block_number,
        block_timestamp:block.timestamp,
        block_blockhash:block.blockhash,
      )

      # === 4) 把“本块最终状态”回写到 tokens 表，确保下一块从最新状态起步 ===
      token.update_columns(
        total_supply:   total_supply,             # 用本方法里累计后的值
        balances:       balances,                 # 最新余额
        premint_minted: token.premint_minted,     # 两条水位
        public_minted:  token.public_minted
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
    # === ESIP-UP: 在某区块中发现并注册带 premint+toadd 的 erc-20 部署 ===
# === ESIP-UP: 在某区块中发现并注册带 premint+toadd 的 erc-20 部署（安全创建版） ===
  def self.discover_up_tokens_in_block!(block_record)
    # 仅在 Sepolia 且达到阈值区块时启用（见 config/initializers/esip_up.rb）
    return unless defined?(EsipUp) && EsipUp.active_for_block?(block_record.block_number)

    # 扫描本区块内新产生的 ethscriptions
    Ethscription.where(block_number: block_record.block_number).find_each do |e|
      # 只处理可解析的 JSON（e.content 是解码后的文本）
      payload = begin
        JSON.parse(e.content)
      rescue JSON::ParserError
        nil
      end
      next unless payload.is_a?(Hash)

      # 1) 只看 erc-20 的 deploy
      next unless payload['p'] == 'erc-20' && payload['op'] == 'deploy'

      # 2) 必须同时带 premint 与 toadd（Strict-UP）
      premint = payload['premint']
      toadd   = payload['toadd']
      next if premint.nil? || toadd.nil?

      # 3) 基本字段齐全
      tick = payload['tick']
      max  = payload['max']
      lim  = payload['lim']
      next if tick.nil? || max.nil? || lim.nil?

      # 4) 已存在同一 deploy 或同名 tick 就跳过
      next if Token.exists?(deploy_ethscription_transaction_hash: e.transaction_hash)
      if Token.exists?(protocol: 'erc-20', tick: tick)
        # 同名 tick 已注册：保持官方行为，不再注册，留作普通 Ethscription
        next
      end

      # 5) 安全创建：前置数值检查 + valid? 校验，不抛错（无效 deploy 当普通 Ethscription）
      max_i = max.to_i
      lim_i = lim.to_i
      pre_i = premint.to_i
      next unless lim_i > 0 && max_i >= 0 && pre_i >= 0 && pre_i <= max_i

      t = Token.new(
        deploy_ethscription_transaction_hash: e.transaction_hash,
        deploy_block_number: e.block_number,
        deploy_transaction_index: e.transaction_index,
        protocol: 'erc-20',
        tick: tick,                # tick 大小写保持官方
        max_supply: max_i,
        mint_amount: lim_i,
        total_supply: 0,
        up_mode: true,
        premint: pre_i,
        toadd: toadd.downcase,     # before_validation 里也会再小写一次
        premint_minted: 0,
        public_minted: 0
      )

      if t.valid?
        t.save!
      else
        Rails.logger.warn("[ESIP-UP] skip invalid deploy tx=#{e.transaction_hash}: #{t.errors.full_messages.join(', ')}")
        next  # 不抛错，忽略 ⇒ 在 token 分支里当普通 Ethscription
      end
    end
  end
end
