"""
LoadEase Database Schemas

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

# Auth and Users
class User(BaseModel):
    email: EmailStr
    password_hash: str
    name: str
    phone: Optional[str] = None
    role: Literal["customer", "owner", "admin"] = "customer"
    is_active: bool = True

# Logistics domain
class Company(BaseModel):
    owner_id: str
    name: str
    reg_number: Optional[str] = None
    vat_number: Optional[str] = None
    documents: List[dict] = []  # [{name, url, type}]
    status: Literal["pending", "verified", "rejected"] = "pending"

class Truck(BaseModel):
    owner_id: str
    company_id: Optional[str] = None
    plate_number: str
    truck_type: Literal[
        "flatbed","box","refrigerated","tanker","lowbed","side_tipper","tautliner"
    ]
    capacity_weight_kg: float
    capacity_volume_cbm: Optional[float] = None
    pallet_capacity: Optional[int] = None
    current_location: Optional[str] = None
    active: bool = True

class Booking(BaseModel):
    customer_id: str
    pickup: str
    dropoff: str
    goods_type: str
    weight_kg: float
    volume_cbm: Optional[float] = None
    pallet_count: Optional[int] = None
    truck_type: str
    pickup_datetime: datetime
    price_total: float
    commission_rate: float = 0.125  # 12.5%
    commission_amount: float
    status: Literal[
        "pending","awaiting_payment","paid","assigned","in_transit","completed","cancelled"
    ] = "pending"
    owner_id: Optional[str] = None
    assigned_truck_id: Optional[str] = None
    notes: Optional[str] = None
    reference: Optional[str] = None

class ReturnLoad(BaseModel):
    truck_id: str
    from_location: str
    to_location: str
    date: datetime
    available: bool = True

class Payment(BaseModel):
    booking_id: str
    method: Literal["payfast","ozow","yoco","snapscan","eft"]
    amount: float
    currency: Literal["ZAR"] = "ZAR"
    status: Literal["pending","paid","failed","refunded"] = "pending"
    gateway_reference: Optional[str] = None

class Subscription(BaseModel):
    owner_id: str
    company_id: Optional[str] = None
    plan: Literal["starter","pro","enterprise"]
    status: Literal["active","past_due","canceled","trial"] = "trial"
    provider: Literal["payfast"] = "payfast"
    next_billing_at: Optional[datetime] = None

class Message(BaseModel):
    booking_id: str
    sender_id: str
    receiver_id: str
    text: str
    read: bool = False

class Notification(BaseModel):
    user_id: str
    type: str
    title: str
    body: Optional[str] = None
    read: bool = False

class Document(BaseModel):
    owner_id: str
    company_id: Optional[str] = None
    filename: str
    url: str
    doc_type: Optional[str] = None
