-- Demo data (synthetic). Safe to re-run.
INSERT INTO sales.customers (customer_id, full_name, email, phone, city, date_of_birth, national_id) VALUES
 (1, 'Priya Sharma',   'priya.sharma@example.com',   '+91-98200-11111', 'Mumbai',    '1990-04-12', 'NID-4411-2290'),
 (2, 'Daniel Okafor',  'daniel.okafor@example.com',  '+1-415-555-0102', 'San Jose',  '1985-09-30', 'NID-8812-1145'),
 (3, 'Mei Lin',        'mei.lin@example.com',        '+65-8123-4567',   'Singapore', '1993-01-21', 'NID-2210-7781'),
 (4, 'Lukas Weber',    'lukas.weber@example.com',    '+49-151-2345678', 'Berlin',    '1978-07-02', 'NID-6650-3302'),
 (5, 'Sofia Rossi',    'sofia.rossi@example.com',    '+39-333-123456',  'Milan',     '1996-11-15', 'NID-9031-5520'),
 (6, 'Arjun Mehta',    'arjun.mehta@example.com',    '+91-99300-22222', 'Bengaluru', '1988-03-08', 'NID-1177-4409')
ON CONFLICT (customer_id) DO NOTHING;

INSERT INTO sales.orders (order_id, customer_id, item, quantity, total, status, created_at) VALUES
 (1001, 1, 'Wireless Headphones', 1,  149.00, 'delivered', now() - interval '20 days'),
 (1002, 1, 'USB-C Hub',           2,   78.00, 'shipped',   now() - interval '3 days'),
 (1003, 2, 'Standing Desk',       1,  549.00, 'delivered', now() - interval '12 days'),
 (1004, 3, 'Mechanical Keyboard', 1,  129.00, 'placed',    now() - interval '1 day'),
 (1005, 4, '4K Monitor',          2,  898.00, 'delivered', now() - interval '30 days'),
 (1006, 5, 'Laptop Stand',        1,   45.00, 'cancelled', now() - interval '7 days'),
 (1007, 6, 'Noise Machine',       1,   89.00, 'shipped',   now() - interval '2 days'),
 (1008, 2, 'Ergonomic Chair',     1,  399.00, 'delivered', now() - interval '15 days')
ON CONFLICT (order_id) DO NOTHING;

INSERT INTO billing.invoices (invoice_id, order_id, amount, status, card_last4, issued_at) VALUES
 ('INV-1001', 1001, 149.00, 'paid',   '4242', now() - interval '20 days'),
 ('INV-1002', 1002,  78.00, 'paid',   '4242', now() - interval '3 days'),
 ('INV-1003', 1003, 549.00, 'paid',   '1881', now() - interval '12 days'),
 ('INV-1004', 1004, 129.00, 'unpaid', NULL,   now() - interval '1 day'),
 ('INV-1005', 1005, 898.00, 'paid',   '0005', now() - interval '30 days'),
 ('INV-1006', 1006,  45.00, 'refunded','7777', now() - interval '7 days'),
 ('INV-1007', 1007,  89.00, 'paid',   '3141', now() - interval '2 days'),
 ('INV-1008', 1008, 399.00, 'paid',   '1881', now() - interval '15 days')
ON CONFLICT (invoice_id) DO NOTHING;

INSERT INTO iam.staff (username, full_name, department, roles, status) VALUES
 ('alice',   'Alice Fernandes', 'Customer Support', ARRAY['support'],                    'active'),
 ('bob',     'Bob Nair',        'Finance',          ARRAY['finance'],                    'active'),
 ('fiona',   'Fiona Kapoor',    'Finance',          ARRAY['finance','finance_manager'],  'active'),
 ('carol',   'Carol Dsouza',    'Platform / IT',    ARRAY['admin'],                      'active'),
 ('ian',     'Ian Thomas',      'Customer Support', ARRAY['intern'],                     'active'),
 ('mallory', 'Mallory Singh',   'Customer Support', ARRAY['support'],                    'suspended')
ON CONFLICT (username) DO NOTHING;

INSERT INTO gov.data_catalog (schema_name, table_name, column_name, classification, owner, retention_days, description) VALUES
 ('sales','customers','customer_id',  'internal',     'sales-data-owner', 2555, 'Surrogate key'),
 ('sales','customers','full_name',    'pii',          'sales-data-owner', 2555, 'Customer name'),
 ('sales','customers','email',        'pii',          'sales-data-owner', 2555, 'Contact email'),
 ('sales','customers','phone',        'pii',          'sales-data-owner', 2555, 'Contact phone'),
 ('sales','customers','city',         'internal',     'sales-data-owner', 2555, 'City'),
 ('sales','customers','date_of_birth','pii',          'sales-data-owner', 2555, 'DOB - not granted to agents'),
 ('sales','customers','national_id',  'restricted',   'dpo',              2555, 'Government ID - never exposed to AI'),
 ('sales','orders','order_id',        'internal',     'sales-data-owner', 2555, 'Order number'),
 ('sales','orders','total',           'confidential', 'finance',          2555, 'Order value'),
 ('billing','invoices','card_last4',  'pii',          'finance',          2555, 'Payment card last 4 digits'),
 ('billing','invoices','amount',      'confidential', 'finance',          2555, 'Invoice amount'),
 ('iam','staff','password_hash',      'restricted',   'security',          365, 'Credential material - never exposed'),
 ('iam','staff','roles',              'internal',     'security',          365, 'Assigned roles')
ON CONFLICT DO NOTHING;
