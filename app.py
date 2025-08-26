from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient
from urllib.parse import quote_plus
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
import bcrypt
import os
from bson import ObjectId
from functools import wraps
import uuid
import re
import json

# Load .env locally (Render will use dashboard env vars)
load_dotenv()  

app = Flask(__name__)

# ✅ Use fixed secret key from env var (important for sessions)
app.secret_key = os.getenv("SECRET_KEY", "dev-change-me")

# ✅ Session cookie config (cross-site between Vercel & Render)
app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,   # Render uses HTTPS
    SESSION_COOKIE_HTTPONLY=True,
)

# ✅ Allow CORS from your frontend (Vercel + local dev)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

from flask_cors import CORS
import re

CORS(
    app,
    supports_credentials=True,
    resources={r"/api/*": {"origins": [
        "http://localhost:5173",
        "https://frontend1-pi-orcin.vercel.app",
        re.compile(r"^https://.*\.vercel\.app$")   # allow preview builds
    ]}}
)


# ✅ MongoDB Connection using env vars
def get_db_connection():
    USERNAME = os.getenv("MONGO_USER")
    PASSWORD = os.getenv("MONGO_PASS")
    HOST = os.getenv("MONGO_HOST", "cluster0.acwgncy.mongodb.net")
    DB_NAME = os.getenv("MONGO_DB", "TimesheetDB")
    APP_NAME = os.getenv("MONGO_APP", "Cluster0")

    # Build URI with proper encoding
    uri = (
        f"mongodb+srv://{quote_plus(USERNAME)}:{quote_plus(PASSWORD)}@{HOST}"
        f"/?retryWrites=true&w=majority&appName={APP_NAME}"
    )

    client = MongoClient(uri, serverSelectionTimeoutMS=10000)
    return client[DB_NAME]

db = get_db_connection()

# Collections
users = db['users']
tasks = db['tasks']
timesheets = db['timesheets']
audits = db['audit_logs']

# Create indexes
users.create_index('username', unique=True)
tasks.create_index('assigned_to')
timesheets.create_index([('username', 1), ('check_in', -1)])

# Custom JSON encoder for ObjectId + datetime
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

app.json_encoder = JSONEncoder

# Utility functions
def log_action(username, action, extra=None):
    doc = {
        'username': username,
        'action': action,
        'timestamp': datetime.now(timezone.utc)
    }
    if extra:
        doc['extra'] = extra
    audits.insert_one(doc)

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_role(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            if session.get('role') not in allowed_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Custom JSON encoder for ObjectId
from bson import ObjectId
import json

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

app.json_encoder = JSONEncoder

# Routes

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        db.command('ping')
        return jsonify({'status': 'healthy', 'database': 'connected'})
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/init', methods=['POST'])
def initialize_admin():
    try:
        # Check if admin exists
        admin_exists = users.find_one({'role': 'Admin'})
        if admin_exists:
            return jsonify({'message': 'Admin already exists'}), 400
        
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Create admin user
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        users.insert_one({
            'username': username,
            'password': hashed_pw,
            'role': 'Admin',
            'created_at': datetime.now(timezone.utc)
        })
        
        log_action(username, 'Admin account created')
        return jsonify({'message': 'Admin created successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        user = users.find_one({'username': username})
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        session['username'] = user['username']
        session['role'] = user['role']
        session['user_id'] = str(user['_id'])
        
        log_action(username, 'Logged in')
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'username': user['username'],
                'role': user['role'],
                'manager': user.get('manager')
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@require_login
def logout():
    username = session.get('username')
    session.clear()
    log_action(username, 'Logged out')
    return jsonify({'message': 'Logout successful'})

@app.route('/api/profile', methods=['GET'])
@require_login
def get_profile():
    username = session.get('username')
    user = users.find_one({'username': username})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'username': user['username'],
        'role': user['role'],
        'manager': user.get('manager'),
        'created_at': user.get('created_at')
    })

@app.route('/api/users', methods=['POST'])
@require_role(['Admin'])
def create_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        manager = data.get('manager')
        
        if not username or not password or not role:
            return jsonify({'error': 'Username, password, and role required'}), 400
        
        if role not in ['Admin', 'Manager', 'Employee']:
            return jsonify({'error': 'Invalid role'}), 400
        
        if users.find_one({'username': username}):
            return jsonify({'error': 'Username already exists'}), 400
        
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user_doc = {
            'username': username,
            'password': hashed_pw,
            'role': role,
            'created_at': datetime.now(timezone.utc)
        }
        
        if manager and role == 'Employee':
            user_doc['manager'] = manager
        
        users.insert_one(user_doc)
        log_action(session.get('username'), f'Created user {username} with role {role}')
        
        return jsonify({'message': 'User created successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
@require_role(['Admin'])
def get_users():
    try:
        user_list = []
        for user in users.find({}, {'password': 0}):
            user['_id'] = str(user['_id'])
            user_list.append(user)
        return jsonify(user_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/managers', methods=['GET'])
@require_role(['Admin'])
def get_managers():
    try:
        manager_list = []
        for manager in users.find({'role': 'Manager'}, {'username': 1}):
            manager_list.append(manager['username'])
        return jsonify(manager_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks', methods=['POST'])
@require_role(['Admin', 'Manager'])
def create_task():
    try:
        data = request.get_json()
        assigned_to = data.get('assigned_to')
        description = data.get('description')
        due_date = data.get('due_date')
        priority = data.get('priority', 'Medium')
        
        if not assigned_to or not description:
            return jsonify({'error': 'Assigned to and description required'}), 400
        
        # Validate assignment based on role
        current_role = session.get('role')
        if current_role == 'Admin':
            target_user = users.find_one({'username': assigned_to, 'role': 'Manager'})
            if not target_user:
                return jsonify({'error': 'Can only assign tasks to Managers'}), 400
        elif current_role == 'Manager':
            target_user = users.find_one({'username': assigned_to, 'role': 'Employee'})
            if not target_user:
                return jsonify({'error': 'Can only assign tasks to Employees'}), 400
        
        task_doc = {
            'assigned_by': session.get('username'),
            'assigned_to': assigned_to,
            'description': description,
            'due_date': due_date,
            'priority': priority,
            'status': 'Pending',
            'assigned_on': datetime.now(timezone.utc),
            'completion_percent': 0,
            'progress_log': []
        }
        
        result = tasks.insert_one(task_doc)
        log_action(session.get('username'), f'Assigned task to {assigned_to}', {'task_id': str(result.inserted_id)})
        
        return jsonify({'message': 'Task created successfully', 'task_id': str(result.inserted_id)})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/my', methods=['GET'])
@require_login
def get_my_tasks():
    try:
        username = session.get('username')
        task_list = []
        
        for task in tasks.find({'assigned_to': username}).sort('assigned_on', -1):
            task['_id'] = str(task['_id'])
            task_list.append(task)
        
        return jsonify(task_list)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/assigned', methods=['GET'])
@require_role(['Admin', 'Manager'])
def get_assigned_tasks():
    try:
        username = session.get('username')
        task_list = []
        
        for task in tasks.find({'assigned_by': username}).sort('assigned_on', -1):
            task['_id'] = str(task['_id'])
            task_list.append(task)
        
        return jsonify(task_list)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tasks/<task_id>/progress', methods=['PUT'])
@require_role(['Employee'])
def update_task_progress(task_id):
    try:
        data = request.get_json()
        percent_added = data.get('percent_added', 0)
        note = data.get('note', '')
        
        try:
            oid = ObjectId(task_id)
        except:
            return jsonify({'error': 'Invalid task ID'}), 400
        
        task = tasks.find_one({'_id': oid, 'assigned_to': session.get('username')})
        if not task:
            return jsonify({'error': 'Task not found or not assigned to you'}), 404
        
        current_percent = task.get('completion_percent', 0)
        new_percent = min(100, max(0, current_percent + percent_added))
        
        if new_percent >= 100:
            status = 'Completed'
        elif new_percent > 0:
            status = 'In Progress'
        else:
            status = 'Pending'
        
        tasks.update_one(
            {'_id': oid},
            {
                '$set': {
                    'completion_percent': new_percent,
                    'status': status
                },
                '$push': {
                    'progress_log': {
                        'date': datetime.now(timezone.utc),
                        'percent_added': percent_added,
                        'note': note
                    }
                }
            }
        )
        
        log_action(session.get('username'), f'Updated task progress by {percent_added}%', {'task_id': task_id})
        
        return jsonify({'message': 'Progress updated successfully', 'new_percent': new_percent, 'status': status})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/checkin', methods=['POST'])
@require_role(['Employee'])
def check_in():
    try:
        username = session.get('username')
        
        # Check if already checked in
        existing = timesheets.find_one({'username': username, 'check_out': None})
        if existing:
            return jsonify({'error': 'Already checked in. Please check out first.'}), 400
        
        now = datetime.now(timezone.utc)
        timesheets.insert_one({
            'username': username,
            'check_in': now,
            'check_out': None,
            'tasks_worked': [],
            'notes': None,
            'completed_today': 0
        })
        
        log_action(username, f'Checked in at {now.isoformat()}')
        return jsonify({'message': 'Checked in successfully', 'check_in_time': now.isoformat()})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/checkout', methods=['POST'])
@require_role(['Employee'])
def check_out():
    try:
        data = request.get_json()
        tasks_worked = data.get('tasks_worked', [])
        notes = data.get('notes', '')
        
        username = session.get('username')
        
        # Find active check-in
        record = timesheets.find_one({'username': username, 'check_out': None})
        if not record:
            return jsonify({'error': 'No active check-in found'}), 400
        
        completed_today = 0
        
        # Update task progress
        for task_work in tasks_worked:
            task_id = task_work.get('task_id')
            percent_added = task_work.get('percent_added', 0)
            task_note = task_work.get('note', '')
            
            try:
                oid = ObjectId(task_id)
                task = tasks.find_one({'_id': oid, 'assigned_to': username})
                
                if task:
                    current_percent = task.get('completion_percent', 0)
                    was_completed = current_percent >= 100
                    new_percent = min(100, max(0, current_percent + percent_added))
                    now_completed = new_percent >= 100
                    
                    if not was_completed and now_completed:
                        completed_today += 1
                    
                    status = 'Completed' if new_percent >= 100 else ('In Progress' if new_percent > 0 else 'Pending')
                    
                    tasks.update_one(
                        {'_id': oid},
                        {
                            '$set': {'completion_percent': new_percent, 'status': status},
                            '$push': {
                                'progress_log': {
                                    'date': datetime.now(timezone.utc),
                                    'percent_added': percent_added,
                                    'note': task_note
                                }
                            }
                        }
                    )
            except Exception as task_error:
                print(f"Error updating task {task_id}: {task_error}")
                continue
        
        # Update timesheet
        checkout_time = datetime.now(timezone.utc)
        timesheets.update_one(
            {'_id': record['_id']},
            {
                '$set': {
                    'check_out': checkout_time,
                    'tasks_worked': tasks_worked,
                    'notes': notes,
                    'completed_today': completed_today
                }
            }
        )
        
        log_action(username, f'Checked out at {checkout_time.isoformat()}', {
            'worked_tasks': len(tasks_worked),
            'completed_today': completed_today
        })
        
        return jsonify({
            'message': 'Checked out successfully',
            'check_out_time': checkout_time.isoformat(),
            'completed_today': completed_today
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/timesheet/today', methods=['GET'])
@require_login
def get_today_timesheet():
    try:
        username = session.get('username')
        today = datetime.now(timezone.utc).date()
        start_of_day = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
        
        records = list(timesheets.find({
            'username': username,
            'check_in': {'$gte': start_of_day}
        }).sort('check_in', -1))
        
        # Convert ObjectId to string for JSON serialization
        for record in records:
            record['_id'] = str(record['_id'])
            # Convert task_id in tasks_worked to string
            for task in record.get('tasks_worked', []):
                if 'task_id' in task:
                    task['task_id'] = str(task['task_id'])
        
        return jsonify(records)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
@require_login
def get_dashboard_stats():
    try:
        username = session.get('username')
        role = session.get('role')
        
        stats = {}
        
        if role == 'Employee':
            # Employee stats
            my_tasks = list(tasks.find({'assigned_to': username}))
            stats['total_tasks'] = len(my_tasks)
            stats['completed_tasks'] = len([t for t in my_tasks if t['status'] == 'Completed'])
            stats['pending_tasks'] = len([t for t in my_tasks if t['status'] == 'Pending'])
            stats['in_progress_tasks'] = len([t for t in my_tasks if t['status'] == 'In Progress'])
            
            # Check if currently checked in
            active_checkin = timesheets.find_one({'username': username, 'check_out': None})
            stats['is_checked_in'] = bool(active_checkin)
            
            # Today's completed tasks
            today = datetime.now(timezone.utc).date()
            start_of_day = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
            today_records = list(timesheets.find({
                'username': username,
                'check_in': {'$gte': start_of_day}
            }))
            stats['completed_today'] = sum(record.get('completed_today', 0) for record in today_records)
            
        elif role == 'Manager':
            # Manager stats
            assigned_tasks = list(tasks.find({'assigned_by': username}))
            stats['assigned_tasks'] = len(assigned_tasks)
            stats['completed_tasks'] = len([t for t in assigned_tasks if t['status'] == 'Completed'])
            stats['pending_tasks'] = len([t for t in assigned_tasks if t['status'] == 'Pending'])
            
            # Team members
            team_members = list(users.find({'manager': username}))
            stats['team_members'] = len(team_members)
            
        elif role == 'Admin':
            # Admin stats
            stats['total_users'] = users.count_documents({})
            stats['total_tasks'] = tasks.count_documents({})
            stats['completed_tasks'] = tasks.count_documents({'status': 'Completed'})
            stats['active_users'] = users.count_documents({'role': {'$ne': 'Admin'}})
        
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit', methods=['GET'])
@require_login
def get_audit_logs():
    try:
        role = session.get('role')
        username = session.get('username')
        
        # Limit audit logs based on role
        if role == 'Admin':
            # Admin can see all audit logs
            logs = list(audits.find().sort('timestamp', -1).limit(50))
        else:
            # Other roles can only see their own logs
            logs = list(audits.find({'username': username}).sort('timestamp', -1).limit(20))
        
        # Convert ObjectId to string
        for log in logs:
            log['_id'] = str(log['_id'])
        
        return jsonify(logs)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)