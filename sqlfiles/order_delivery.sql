USE vasundhara_agro_db;

SELECT
    o.id AS order_id,
    o.tracking_number,
    o.customer_name,
    o.customer_phone,
    o.delivery_address,
    o.delivery_city,
    o.delivery_pincode,
    o.delivery_instructions,
    o.payment_method,
    o.total_amount,
    o.status,
    o.created_at,
    u.username,
    u.email,
    GROUP_CONCAT(CONCAT(p.name, ' x', oi.quantity) SEPARATOR ', ') AS ordered_items
FROM orders o
JOIN users u ON o.user_id = u.id
LEFT JOIN order_items oi ON o.id = oi.order_id
LEFT JOIN products p ON oi.product_id = p.id
GROUP BY
    o.id,
    o.tracking_number,
    o.customer_name,
    o.customer_phone,
    o.delivery_address,
    o.delivery_city,
    o.delivery_pincode,
    o.delivery_instructions,
    o.payment_method,
    o.total_amount,
    o.status,
    o.created_at,
    u.username,
    u.email
ORDER BY o.created_at DESC;
