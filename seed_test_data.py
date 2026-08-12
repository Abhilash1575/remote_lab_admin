"""One-off script: seed a local test DB with an admin, a student, an
experiment, a LabPi pointing at this box's own real lab-pi process, and a
booking with a real multi-minute duration. Only for the joint local test —
not meant to persist."""
from datetime import datetime, timedelta
from app import app, db
from models import User, Experiment, LabPi, Booking, Department
import secrets, string

with app.app_context():
    db.create_all()

    dept = Department.query.filter_by(code='TEST').first()
    if not dept:
        dept = Department(name='Test Dept', code='TEST')
        db.session.add(dept)
        db.session.commit()

    student = User.query.filter_by(email='student@test.local').first()
    if not student:
        student = User(email='student@test.local', full_name='Test Student', username='teststudent', department_id=dept.id, is_admin=False, profile_complete=True)
        student.password = 'TestPass123!'
        db.session.add(student)
        db.session.commit()
    print(f"Student id={student.id}")

    exp = Experiment.query.filter_by(name='Local Test Experiment').first()
    if not exp:
        exp = Experiment(name='Local Test Experiment', description='joint local test', max_duration=30, board_type='arduino', active=True)
        db.session.add(exp)
        db.session.commit()
    print(f"Experiment id={exp.id}")

    lab_pi = LabPi.query.filter_by(lab_pi_id='raspberrypi').first()
    if not lab_pi:
        lab_pi = LabPi(lab_pi_id='raspberrypi', name='Local test lab-pi', experiment_id=exp.id, ip_address='127.0.0.1', status='ONLINE', last_heartbeat=datetime.utcnow(), board_type='arduino')
        db.session.add(lab_pi)
    else:
        lab_pi.experiment_id = exp.id
        lab_pi.ip_address = '127.0.0.1'
        lab_pi.status = 'ONLINE'
        lab_pi.last_heartbeat = datetime.utcnow()
    db.session.commit()
    print(f"LabPi id={lab_pi.id}, status={lab_pi.status}, ip={lab_pi.ip_address}")

    session_key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    now = datetime.now()
    booking = Booking(
        user_id=student.id,
        experiment_id=exp.id,
        start_time=now - timedelta(minutes=1),
        end_time=now + timedelta(minutes=29),
        status='UPCOMING',
        session_key=session_key,
    )
    db.session.add(booking)
    db.session.commit()
    print(f"Booking id={booking.id}, session_key={session_key}, start={booking.start_time}, end={booking.end_time}")
    print(f"STUDENT_ID={student.id}")
