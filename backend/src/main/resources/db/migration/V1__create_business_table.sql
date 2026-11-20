CREATE TABLE business (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name           VARCHAR(150) NOT NULL,
    currency       VARCHAR(3)   NOT NULL,
    invoice_prefix VARCHAR(10)  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
