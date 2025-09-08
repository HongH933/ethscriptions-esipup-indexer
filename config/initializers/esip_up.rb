# config/initializers/esip_up.rb
module EsipUp
  # 只在 Sepolia（11155111）启用；你也可以用 ENV['ETHEREUM_NETWORK'] == 'sepolia' 判定
  CHAIN_ID = Integer(ENV.fetch('CHAIN_ID', '11155111'))
  ACTIVATION_BLOCK = Integer(ENV.fetch('ESIP_UP_ACTIVATION_BLOCK', '9157000'))

  def self.active_for_block?(block_number)
    CHAIN_ID == 11155111 && block_number.to_i >= ACTIVATION_BLOCK
  end
end
