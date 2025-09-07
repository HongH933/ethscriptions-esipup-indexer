class AddEsipUpColumnsToTokens < ActiveRecord::Migration[7.0]
  def up
    change_table :tokens do |t|
      t.boolean :up_mode,         null: false, default: false
      t.bigint  :premint,         null: false, default: 0
      t.text    :toadd            # 入库统一小写，逻辑在模型里做，All data entered into the database is lowercase, and the logic is implemented in the model.
      t.bigint  :premint_minted,  null: false, default: 0
      t.bigint  :public_minted,   null: false, default: 0
    end

    # —— 软约束（Postgres CHECK）；不存在则添加 —— #
    execute <<~SQL
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'tokens_premint_nonneg'
        ) THEN
          ALTER TABLE tokens
          ADD CONSTRAINT tokens_premint_nonneg CHECK (premint >= 0);
        END IF;
      END$$;
    SQL

    execute <<~SQL
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'tokens_premint_minted_nonneg'
        ) THEN
          ALTER TABLE tokens
          ADD CONSTRAINT tokens_premint_minted_nonneg CHECK (premint_minted >= 0);
        END IF;
      END$$;
    SQL

    execute <<~SQL
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint WHERE conname = 'tokens_public_minted_nonneg'
        ) THEN
          ALTER TABLE tokens
          ADD CONSTRAINT tokens_public_minted_nonneg CHECK (public_minted >= 0);
        END IF;
      END$$;
    SQL

    # 在 DB 层加上限约束，可以解开下面两条：
    # execute "ALTER TABLE tokens ADD CONSTRAINT tokens_premint_le_max CHECK (premint <= max_supply);"
    # execute "ALTER TABLE tokens ADD CONSTRAINT tokens_total_minted_le_max CHECK ((premint_minted + public_minted) <= max_supply);"
  end

  def down
    # 先删约束，再删列，避免回滚失败
    execute "ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_total_minted_le_max;"
    execute "ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_premint_le_max;"
    execute "ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_public_minted_nonneg;"
    execute "ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_premint_minted_nonneg;"
    execute "ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_premint_nonneg;"

    change_table :tokens do |t|
      t.remove :public_minted if column_exists?(:tokens, :public_minted)
      t.remove :premint_minted if column_exists?(:tokens, :premint_minted)
      t.remove :toadd if column_exists?(:tokens, :toadd)
      t.remove :premint if column_exists?(:tokens, :premint)
      t.remove :up_mode if column_exists?(:tokens, :up_mode)
    end
  end
end
