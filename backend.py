from fastapi import FastAPI, HTTPException, Cookie, Response, Request
from supabase import create_client
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import jwt, JWTError
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import json
from fastapi import Body
from datetime import date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Setting up the app and adding the middleware:-
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_headers=['*'],
    allow_methods=['*']
)

# IMPORTANT STUFF:-
SUPABASE_URL = 'https://fqrzzacxgbkffqphmhpd.supabase.co'
SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZxcnp6YWN4Z2JrZmZxcGhtaHBkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2MjU4NjA0NCwiZXhwIjoyMDc4MTYyMDQ0fQ.iROXsacLOGJZtuqqB02rVVQKNFA_B-efxQnw2YGWXMk'

JWT_SECRET = 'JFSh3XqtWw5lnvGvqeeE9KepRwe8Etly44EMStUVBWrVZ9BKkQm8qZdxLBjj10R5nfpU4ClG0biSie3Ya3N20QNRuCEml63JR0yI4GEdpyZn4V0qrpKdfdZAZC1cOI8i'
supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Schemas
class UserSignup(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class PatientDetails(BaseModel):
    name: str
    email: str
    phone: int
    next_visit: str
    reason: str

class DeletePatient(BaseModel):
    patient_id: str

class ClinicTimeSlots(BaseModel):
    ts_string: str

class PatientAppointments(BaseModel):
    patient_id: str

class DaySlotRequest(BaseModel):
    token: str
    date: date

class ModifySlots(BaseModel):
    token: str
    date: date
    slot: str



# Utilities:-
algorithm = 'HS256'
encryption_context = CryptContext(schemes=['bcrypt_sha256'], deprecated='auto')

def hash_password(password: str):
    return encryption_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return encryption_context.verify(plain_password, hashed_password)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=180)
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=algorithm)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=algorithm)
        return payload
    except JWTError:
        return None
    
import secrets
import string

def generate_token(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))



@app.post('/signup')
def user_signup(user_details: UserSignup, response: Response):
    existing = supabase_client.table('clinics').select('*').eq('email', user_details.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail=f'Email: {user_details.email} already exists !')

    hashed_password = hash_password(user_details.password)

    new_user = {
        'email': user_details.email,
        'clinic_name': user_details.username,
        'password_hash': hashed_password
    }

    refresh_token = create_token(data={'sub': user_details.email})
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite='lax',
        max_age=60 * 60 * 24 * 180
    )

    added = supabase_client.table('clinics').insert(new_user).execute()
    data = added.data[0]
    return {'username': data["clinic_name"], "signup": "success", "id": data["id"]}

@app.post('/login')
def user_login(user_details: UserLogin, response: Response):
    user = supabase_client.table('clinics').select('*').eq('email', user_details.email).single().execute()

    if not user.data:
        raise HTTPException(status_code=400, detail=f'User with email: {user_details.email} doesnt exist.')

    if not verify_password(user_details.password, user.data['password_hash']):
        raise HTTPException(status_code=400, detail=f'Incorrect password entered !')

    refresh_token = create_token(data={'sub': user_details.email})
    response.set_cookie(
        key='refresh_token',
        value=refresh_token,
        samesite='lax',
        httponly=True,
        secure=False,
        max_age=60 * 60 * 24 * 180
    )


    return {"username": user.data["clinic_name"], "message": "login:success"}

@app.post("/refresh")
def user_refresh(response: Response, refresh_token: str = Cookie(None)):
    print("REFRESH TOKEN:", refresh_token)
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    email = payload.get("sub")

    result = (
        supabase_client
        .table("clinics")
        .select("*")
        .eq("email", email)
        .execute()
    )

    if not result.data:
        raise HTTPException(status_code=401, detail="User not found")

    user = result.data[0]

    new_token = create_token({"sub": email})
    response.set_cookie(
        key="refresh_token",
        value=new_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 180
    )

    #Returning the patient list:-
    patient_list = (
        supabase_client
        .table("patients")
        .select("*")
        .eq("clinic_id", user["id"])
        .execute()
    )

    return {
        "username": user["clinic_name"],
        "email": user["email"],
        "id": user["id"],
        "status": user["is_active"],
        "patient_list":patient_list
    }


@app.post("/add-patient")
def add_patient(patient_details: PatientDetails, refresh_token: str = Cookie(None)):
    print("REFRESH TOKEN:", refresh_token)
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    email = payload.get("sub")

    result = (
        supabase_client
        .table("clinics")
        .select("*")
        .eq("email", email)
        .execute()
    )

    if not result.data:
        raise HTTPException(status_code=401, detail="User not found")

    user = result.data[0]
    clinic_id = user["id"]
    new_entry = {
        "clinic_id": clinic_id,
        "name":patient_details.name,
        "email": patient_details.email,
        "phone": patient_details.phone,
        "next_visit": patient_details.next_visit,
        "reason": patient_details.reason}
    patient_result = supabase_client.table("patients").insert(new_entry).execute()
    new_entry_data = patient_result.data[0]

    return {
        "username": new_entry_data["name"],
        "email": new_entry_data["email"],
        "patient_id": new_entry_data["id"]
        
    }
@app.post("/delete-patient")
def delete_patient(data: DeletePatient):
    try:
        deleted_patient = supabase_client.table("patients").delete().eq("id", data.patient_id).execute()
        return {"message":"del-success"}
    except:
        return {"message":"del-fail"}
    
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("refresh_token")
    return {"ok": True}



@app.post("/save-clinic-slots")
def save_clinic_slots(
    availability: list = Body(...),
    refresh_token: str = Cookie(None)
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = payload.get("sub")

    supabase_client \
        .table("clinics") \
        .update({"clinic_slots": json.dumps(availability)}) \
        .eq("email", email) \
        .execute()                          

    return {"status": "success"}

@app.post("/get-clinic-slots")
def get_clinic_slots(refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    email = payload.get("sub")

    clinic_res = (
        supabase_client
        .table("clinics")
        .select("clinic_slots")
        .eq("email", email)
        .single()
        .execute()                     
    )

    if not clinic_res.data:
        raise HTTPException(status_code=404, detail="Clinic not found")

    return {
        "clinic_slots": clinic_res.data["clinic_slots"]  # can be None
    }
@app.post("/add-appointment")
def add_patient_appointment(appointmentSchema: PatientAppointments):
    patient_id = appointmentSchema.patient_id
    token = generate_token()
    new_appointment = {
        "patient_id": patient_id,
        "token": token
    }
    add_appointment = supabase_client.table("appointments").insert(new_appointment).execute()

    data = add_appointment.data[0]
    return {"id": data["id"],
            "token": data["token"]}
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta, timezone

templates = Jinja2Templates(directory="templates")

@app.get("/book/{token}", response_class=HTMLResponse)
def book_appointment_page(request: Request, token: str):
    # 1️⃣ Fetch appointment by token
    appointment_res = (
        supabase_client
        .table("appointments")
        .select("*")
        .eq("token", token)
        .single()
        .execute()
    )
    if not appointment_res.data:
        raise HTTPException(status_code=404, detail="Invalid token")

    appointment = appointment_res.data

    # 2️⃣ Reject used or expired tokens
    if appointment["used"]:
        raise HTTPException(status_code=400, detail="Token already used")
    if appointment["expired"]:
        raise HTTPException(status_code=400, detail="Token expired")

    # Optional: auto-expire after 7 days
    created_at = datetime.fromisoformat(appointment["created_at"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    if created_at < now - timedelta(days=7):
        raise HTTPException(status_code=400, detail="Token expired")

    # 3️⃣ Fetch patient
    patient_res = (
        supabase_client
        .table("patients")
        .select("*")
        .eq("id", appointment["patient_id"])
        .single()
        .execute()
    )
    patient = patient_res.data
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # 4️⃣ Fetch clinic
    clinic_res = (
        supabase_client
        .table("clinics")
        .select("*")
        .eq("id", patient["clinic_id"])
        .single()
        .execute()
    )
    clinic = clinic_res.data
    if not clinic:
        raise HTTPException(status_code=404, detail="Clinic not found")

    # 5️⃣ Compute next 7 days excluding today
    next_7_days = [(now + timedelta(days=i)).date() for i in range(1, 8)]

    # 6️⃣ Render template
    return templates.TemplateResponse(
        "book_appointment.html",
        {
            "request": request,
            "patient_name": patient["name"],
            "patient_email": patient["email"],
            "clinic_name": clinic["clinic_name"],
            "next_days": next_7_days,
            "token": token
        }
    )


from datetime import date
import calendar
import json



class DaySlotRequest(BaseModel):
    token: str
    date: date

@app.post("/day-slots")
def get_or_create_day_slots(payload: DaySlotRequest):
    # 1. Validate appointment
    appointment_res = (
        supabase_client
        .table("appointments")
        .select("*")
        .eq("token", payload.token)
        .limit(1)
        .execute()
    )

    if not appointment_res.data:
        raise HTTPException(status_code=404, detail="Invalid token")

    appointment = appointment_res.data[0]

    if appointment["used"] or appointment["expired"]:
        raise HTTPException(status_code=400, detail="Token invalid")

    # 2. Get clinic_id
    patient_res = (
        supabase_client
        .table("patients")
        .select("clinic_id")
        .eq("id", appointment["patient_id"])
        .limit(1)
        .execute()
    )

    clinic_id = patient_res.data[0]["clinic_id"]

    # 3. Check existing day_slots
    existing = (
        supabase_client
        .table("day_slots")
        .select("*")
        .eq("clinic_id", clinic_id)
        .eq("slot_date", payload.date.isoformat())
        .limit(1)
        .execute()
    )

    if existing.data:
        return {
            "date": payload.date,
            "slots": json.loads(existing.data[0]["slots"])  # convert back to dict
        }

    # 4. Weekday (mon/tue/...)
    weekday = calendar.day_name[payload.date.weekday()].lower()[:3]

    # 5. Fetch clinic slots
    clinic_res = (
        supabase_client
        .table("clinics")
        .select("clinic_slots")
        .eq("id", clinic_id)
        .limit(1)
        .execute()
    )

    clinic_slots = clinic_res.data[0]["clinic_slots"]

    # convert JSON string → Python list
    if isinstance(clinic_slots, str):
        clinic_slots = json.loads(clinic_slots)

    # 6. Build slots for the specific day
    slots_for_day = {}
    for day_obj in clinic_slots:
        if weekday in day_obj:
            for slot in day_obj[weekday]:
                slots_for_day[slot] = "free"
            break

    # 7. Insert into day_slots (as text)
    new_day_slot = {
        "clinic_id": clinic_id,
        "slot_date": payload.date.isoformat(),
        "slots": json.dumps(slots_for_day)  # store as JSON string in text column
    }

    supabase_client.table("day_slots").insert(new_day_slot).execute()

    return {
        "date": payload.date,
        "slots": slots_for_day
    }
@app.post("/add-slots")
def modify_slots(details: ModifySlots):
    # 1️⃣ Validate appointment token
    appointment_res = (
        supabase_client
        .table("appointments")
        .select("*")
        .eq("token", details.token)
        .single()
        .execute()
    )

    if not appointment_res.data:
        raise HTTPException(status_code=404, detail="Invalid token")

    appointment = appointment_res.data

    if appointment["used"] or appointment["expired"]:
        raise HTTPException(status_code=400, detail="Token already used or expired")

    # 2️⃣ Get patient
    patient_res = (
        supabase_client
        .table("patients")
        .select("*")
        .eq("id", appointment["patient_id"])
        .single()
        .execute()
    )

    if not patient_res.data:
        raise HTTPException(status_code=404, detail="Patient not found")

    patient = patient_res.data
    clinic_id = patient["clinic_id"]

    # 3️⃣ Fetch day_slots row
    day_slot_res = (
        supabase_client
        .table("day_slots")
        .select("*")
        .eq("clinic_id", clinic_id)
        .eq("slot_date", details.date.isoformat())
        .single()
        .execute()
    )

    if not day_slot_res.data:
        raise HTTPException(status_code=404, detail="Day slots not found")

    day_slot = day_slot_res.data

    # 4️⃣ Parse slots JSON (TEXT → dict)
    slots = json.loads(day_slot["slots"])

    if details.slot not in slots:
        raise HTTPException(status_code=400, detail="Slot does not exist")

    if slots[details.slot] != "free":
        raise HTTPException(status_code=400, detail="Slot already booked")

    # 5️⃣ Mark slot as booked
    slots[details.slot] = "booked"

    # 6️⃣ Update day_slots
    supabase_client \
        .table("day_slots") \
        .update({
            "slots": json.dumps(slots),
            "updated_at": datetime.utcnow().isoformat()
        }) \
        .eq("id", day_slot["id"]) \
        .execute()

    # 7️⃣ Update patient next_visit
    supabase_client \
        .table("patients") \
        .update({
            "next_visit": details.date.isoformat()
        }) \
        .eq("id", patient["id"]) \
        .execute()
    
    # 8️⃣ INSERT appointment log (🔥 THIS IS THE FIX)
    supabase_client.table("ap_responses").insert({
        "clinic_id": clinic_id,
        "name": patient["name"],
        "date": details.date.isoformat(),
        "slot": details.slot
    }).execute()

    # 8️⃣ Mark appointment token as used
    supabase_client \
        .table("appointments") \
        .update({
            "used": True
        }) \
        .eq("id", appointment["id"]) \
        .execute()
    
    

    return {
        "status": "success",
        "message": "Appointment confirmed",
        "date": details.date,
        "slot": details.slot
    }

# ================= SMTP CONFIG =================
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_USER = "noreply.updates.app@gmail.com"
EMAIL_PASS = "mgtv mbmp xbcc odmv"  # your app password

# ================= SCHEMA =================
class SendEmail(BaseModel):
    clinic_name: str
    link: str
    patient_email: str

# ================= ENDPOINT =================
@app.post("/send-reminder-email")
def send_reminder_email(data: SendEmail):
    try:
        # 1️⃣ Create email
        subject = f"Appointment Reminder from {data.clinic_name}"
        body = f"Hi,\n\nThis is a reminder for your upcoming appointment at {data.clinic_name}.\nPlease confirm your slot using this link:\n{data.link}\n\n— {data.clinic_name}"

        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = data.patient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # 2️⃣ Send email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)

        return {"status": "success", "message": f"Email sent to {data.patient_email}"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

@app.post("/upcoming")
def upcoming_patients(response: Response, refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    email = payload.get("sub")

    result = (
        supabase_client
        .table("clinics")
        .select("*")
        .eq("email", email)
        .execute()
    )

    if not result.data:
        raise HTTPException(status_code=401, detail="User not found")

    user = result.data[0]



    #Returning the patient list:-
    upcoming_list = (
        supabase_client
        .table("ap_responses")
        .select("*")
        .eq("clinic_id", user["id"])
        .execute()
    )

    return {
        "username": user["clinic_name"],
        "email": user["email"],
        "id": user["id"],
        "upcoming_list":upcoming_list
    }





def get_product_id(form_data):
    user_id = form_data.get("url_params[user_id]")
    product_id =  form_data.get("product_id")
    res = [user_id,product_id]
    return res

@app.post("/user-id")
def get_user_id(refresh_token: str = Cookie(None)):
    print("REFRESH TOKEN:", refresh_token)
    if not refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token")

    payload = verify_token(refresh_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Invalid refresh token")

    email = payload.get("sub")

    result = (
        supabase_client
        .table("clinics")
        .select("*")
        .eq("email", email)
        .execute()
    )

    if not result.data:
        raise HTTPException(status_code=401, detail="User not found")

    user = result.data[0]




    return {
        "id": user["id"]        
    }

@app.post("/purchase")
async def gumroad_webhook(request: Request):
    payload = await request.form()

    product_id = get_product_id(payload)

    if product_id[1] == 'uCF_fviEP2kfAIIT4ttqIg==':

        result = (
            supabase_client
            .table("clinics")
            .update({"is_active": True})
            .eq("id", product_id[0])
            .execute()
        )

    user = result.data[0]


    print("PRODUCT ID:", product_id)
    print("Full payload:-")
    print(payload)

    return {"status": "ok", "updated_name": user["clinic_name"]}


