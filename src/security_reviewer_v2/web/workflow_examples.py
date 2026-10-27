"""Editable product requirements examples, independent of benchmark answers."""


def order_service_example():
    accounts = [{"id": name, "role": "admin" if name == "admin" else "user", "login_path": "/auth/login", "encoding": "json",
                 "username_field": "username", "password_field": "password", "session": "bearer", "token_path": "access_token",
                 "verify_path": "/me", "identity_path": "username"} for name in ("user_a", "user_b", "admin")]

    def request(method, path, *, actor="user_a", body=None, capture=None, expect=(200,), security=False, assertions=None):
        s = {"actor": actor, "method": method, "path": path, "expect_status": list(expect), "security_check": security}
        if body is not None:
            s["body"] = body
        if capture:
            s["capture"] = capture
        if assertions:
            s["assertions"] = assertions
        return s

    def create(actor="user_a"):
        return request("POST", "/orders", actor=actor, body={"item": "workflow-test", "quantity": 1, "unit_price": 100}, capture={"order_id": "id"}, expect=(200, 201))

    def workflow(name, title, steps, severity="high"):
        return {"id": name, "title": title, "severity": severity, "steps": steps}

    workflows = [
        workflow("purchase", "Owner can create, pay and read their invoice", [create(), request("POST", "/orders/{{order_id}}/pay", capture={"invoice_id": "id"}), request("GET", "/invoices/{{invoice_id}}")], "low"),
        workflow("order_owner", "Only the owner can read an order", [create("user_b"), request("GET", "/orders/{{order_id}}", actor="user_b"), request("GET", "/orders/{{order_id}}", expect=(403, 404), security=True)]),
        workflow("invoice_owner", "Only the owner can read an invoice", [create("user_b"), request("POST", "/orders/{{order_id}}/pay", actor="user_b", capture={"invoice_id": "id"}), request("GET", "/invoices/{{invoice_id}}", actor="user_b"), request("GET", "/invoices/{{invoice_id}}", expect=(403, 404), security=True)]),
        workflow("admin_users", "User listing requires the admin role", [request("GET", "/admin/users", actor="admin"), request("GET", "/admin/users", expect=(403, 404), security=True)]),
        workflow("admin_jobs", "Job listing requires the admin role", [request("GET", "/admin/jobs", actor="admin"), request("GET", "/admin/jobs", expect=(403, 404), security=True)]),
        workflow("payment_replay", "An already paid order rejects another payment", [create(), request("POST", "/orders/{{order_id}}/pay"), request("POST", "/orders/{{order_id}}/pay", expect=(400, 409, 422), security=True)]),
        workflow("paid_cancel", "Paid orders require a refund workflow before cancellation", [create(), request("POST", "/orders/{{order_id}}/pay"), request("POST", "/orders/{{order_id}}/cancel", expect=(400, 409, 422), security=True)]),
        workflow("coupon_bounds", "Discounts over 100 percent are rejected", [create(), request("POST", "/orders/{{order_id}}/apply-coupon", body={"code": "WELCOME20", "discount": 150}, expect=(400, 422), security=True)]),
        workflow("negative_price", "Negative order prices are rejected", [request("POST", "/orders", body={"item": "workflow-test", "quantity": 1, "unit_price": -1}, expect=(400, 422), security=True)]),
        workflow("order_initial_state", "New orders cannot start as paid", [request("POST", "/orders", body={"item": "workflow-test", "quantity": 1, "unit_price": 100, "status": "paid"}, expect=(400, 422), security=True)]),
        workflow("owner_assignment", "Users cannot create orders for another owner", [request("GET", "/me", actor="user_b", capture={"other_id": "id"}), request("POST", "/orders", body={"item": "workflow-test", "quantity": 1, "unit_price": 100, "owner_id": "{{other_id}}"}, expect=(400, 403, 422), security=True)]),
        workflow("worker_role", "Users cannot submit an admin job", [request("POST", "/jobs", body={"kind": "report", "payload": {}, "run_as": "admin"}, expect=(400, 403, 422), security=True)]),
        workflow("debug_access", "Debug configuration is unavailable anonymously", [request("GET", "/debug/config", actor="anonymous", expect=(401, 403, 404), security=True)]),
    ]
    return {"version": 1, "accounts": accounts, "workflows": workflows, "allow_mutation": True, "reset": "fresh_stack", "max_requests": 100, "timeout_seconds": 5, "max_seconds": 300}
