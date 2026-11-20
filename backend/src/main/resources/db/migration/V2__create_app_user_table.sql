CREATE TABLE app_user (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    business_id   BIGINT       NOT NULL REFERENCES business (id),
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20)  NOT NULL,
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_app_user_role CHECK (role IN ('OWNER', 'ACCOUNTANT', 'VIEWER'))
);

CREATE INDEX idx_app_user_business_id ON app_user (business_id);
