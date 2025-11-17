import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User, Company, Truck, Booking, Payment, ReturnLoad, Subscription, Message, Document

APP_NAME = "LoadEase"
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    role: str


class AuthLogin(BaseModel):
    email: EmailStr
    password: str


def require_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return {"user_id": payload.get("sub"), "role": payload.get("role")}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/")
def read_root():
    return {"message": f"{APP_NAME} API is running"}


# Auth endpoints
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: AuthRegister):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        name=payload.name,
        phone=payload.phone,
        role=payload.role if payload.role in ["customer", "owner", "admin"] else "customer",
    )
    user_id = create_document("user", user)
    token = create_access_token(user_id, user.role)
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: AuthLogin):
    u = db["user"].find_one({"email": payload.email})
    if not u or not verify_password(payload.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(str(u.get("_id")), u.get("role", "customer"))
    return TokenResponse(access_token=token)


# Admin light endpoints
@app.get("/admin/users")
def admin_users(current=Depends(require_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return {"users": get_documents("user")}


@app.get("/admin/bookings")
def admin_bookings(current=Depends(require_user)):
    if current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return {"bookings": get_documents("booking")}


# Company and Document upload
@app.post("/owner/company")
def register_company(name: str = Form(...), reg_number: str = Form(None), vat_number: str = Form(None), current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Only owners can register companies")
    company = Company(owner_id=current["user_id"], name=name, reg_number=reg_number, vat_number=vat_number)
    company_id = create_document("company", company)
    return {"company_id": company_id}


@app.post("/owner/company/{company_id}/documents")
async def upload_document(company_id: str, file: UploadFile = File(...), current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    url = f"/uploads/{company_id}/{file.filename}"
    doc = Document(owner_id=current["user_id"], company_id=company_id, filename=file.filename, url=url)
    _id = create_document("document", doc)
    db["company"].update_one({"_id": {"$exists": True}, "owner_id": current["user_id"]}, {"$push": {"documents": {"filename": file.filename, "url": url}}})
    return {"document_id": _id, "url": url}


# Trucks
@app.post("/owner/trucks")
def add_truck(payload: Truck, current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    t = payload.model_dump()
    t["owner_id"] = current["user_id"]
    truck_id = create_document("truck", t)
    return {"truck_id": truck_id}


@app.get("/owner/trucks")
def list_trucks(current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    trucks = get_documents("truck", {"owner_id": current["user_id"]})
    return {"trucks": trucks}


# Booking flow
class BookingCreate(BaseModel):
    pickup: str
    dropoff: str
    goods_type: str
    weight_kg: float
    volume_cbm: Optional[float] = None
    pallet_count: Optional[int] = None
    truck_type: str
    pickup_datetime: datetime


def calculate_price(weight_kg: float, distance_km: float, commission_rate: float):
    base_rate_per_km = 18.0  # ZAR per km baseline
    weight_factor = 1 + min(weight_kg / 10000, 1)
    price_before_commission = base_rate_per_km * distance_km * weight_factor
    commission = price_before_commission * commission_rate
    total = price_before_commission + commission
    return price_before_commission, commission, total


@app.post("/customer/bookings")
def create_booking(payload: BookingCreate, current=Depends(require_user)):
    if current["role"] not in ["customer", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")

    # For demo purposes, approximate distance as 500km
    distance_km = 500.0
    commission_rate = 0.12
    base, commission, total = calculate_price(payload.weight_kg, distance_km, commission_rate)

    booking = Booking(
        customer_id=current["user_id"],
        pickup=payload.pickup,
        dropoff=payload.dropoff,
        goods_type=payload.goods_type,
        weight_kg=payload.weight_kg,
        volume_cbm=payload.volume_cbm,
        pallet_count=payload.pallet_count,
        truck_type=payload.truck_type,
        pickup_datetime=payload.pickup_datetime,
        price_total=round(total, 2),
        commission_rate=commission_rate,
        commission_amount=round(commission, 2),
        status="awaiting_payment",
        reference=f"LE-{int(datetime.utcnow().timestamp())}"
    )

    booking_id = create_document("booking", booking)
    return {"booking_id": booking_id, "amount": booking.price_total, "reference": booking.reference}


@app.get("/customer/bookings")
def list_bookings(current=Depends(require_user)):
    if current["role"] not in ["customer", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    bookings = get_documents("booking", {"customer_id": current["user_id"]})
    return {"bookings": bookings}


# Owner accepts/declines
class BookingAction(BaseModel):
    booking_id: str  # using reference as id for simplicity
    accept: bool
    truck_id: Optional[str] = None


@app.post("/owner/bookings/decision")
def booking_decision(payload: BookingAction, current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    if payload.accept:
        db["booking"].update_one({"reference": payload.booking_id}, {"$set": {"status": "assigned", "owner_id": current["user_id"], "assigned_truck_id": payload.truck_id}})
    else:
        db["booking"].update_one({"reference": payload.booking_id}, {"$set": {"status": "pending"}})
    return {"ok": True}


# Payments (gateways mocked)
class PaymentInit(BaseModel):
    booking_reference: str
    method: str  # payfast, ozow, yoco, snapscan, eft


@app.post("/payments/init")
def init_payment(payload: PaymentInit, current=Depends(require_user)):
    b = db["booking"].find_one({"reference": payload.booking_reference})
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")
    pay = Payment(booking_id=str(b.get("_id")), method=payload.method, amount=b.get("price_total", 0))
    payment_id = create_document("payment", pay)
    db["booking"].update_one({"reference": payload.booking_reference}, {"$set": {"status": "paid" if payload.method == "eft" else "awaiting_payment"}})
    return {"payment_id": payment_id, "pay_url": f"https://gateway.mock/{payload.method}?ref={payload.booking_reference}"}


@app.post("/payments/webhook/{gateway}")
def payment_webhook(gateway: str, reference: str):
    db["booking"].update_one({"reference": reference}, {"$set": {"status": "paid"}})
    return {"ok": True}


# Return loads: when a truck finishes A->B, auto-list B->A
class JobComplete(BaseModel):
    reference: str
    actual_dropoff: str
    return_to: str
    truck_id: str


@app.post("/owner/job/complete")
def complete_job(payload: JobComplete, current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    db["booking"].update_one({"reference": payload.reference}, {"$set": {"status": "completed"}})
    rl = ReturnLoad(truck_id=payload.truck_id, from_location=payload.actual_dropoff, to_location=payload.return_to, date=datetime.utcnow())
    rl_id = create_document("returnload", rl)
    return {"return_load_id": rl_id}


@app.get("/owner/return-loads")
def list_return_loads(current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    loads = get_documents("returnload", {"available": True})
    return {"return_loads": loads}


# Subscriptions (mock via PayFast)
class SubscriptionCreate(BaseModel):
    plan: str  # starter, pro, enterprise


@app.post("/owner/subscription")
def create_subscription(payload: SubscriptionCreate, current=Depends(require_user)):
    if current["role"] not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    sub = Subscription(owner_id=current["user_id"], plan=payload.plan)
    sub_id = create_document("subscription", sub)
    return {"subscription_id": sub_id, "redirect": f"https://payfast.mock/subscribe?plan={payload.plan}"}


# Simple messaging
class MessageCreate(BaseModel):
    booking_reference: str
    text: str


@app.post("/messages")
def send_message(payload: MessageCreate, current=Depends(require_user)):
    b = db["booking"].find_one({"reference": payload.booking_reference})
    if not b:
        raise HTTPException(status_code=404, detail="Booking not found")
    receiver = b.get("owner_id") if current["user_id"] == b.get("customer_id") else b.get("customer_id")
    msg = Message(booking_id=str(b.get("_id")), sender_id=current["user_id"], receiver_id=str(receiver), text=payload.text)
    mid = create_document("message", msg)
    return {"message_id": mid}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
