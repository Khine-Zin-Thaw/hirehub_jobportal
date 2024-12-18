from datetime import datetime, timedelta
import sqlite3
import os
import re
import time
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, request, redirect, url_for, session
from flask import flash, jsonify, send_from_directory, send_file, abort
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = 'secret'
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)


# Configuration
static_folder = 'static'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

# Folder Paths
UPLOAD_FOLDERS = {
    'employer_images': os.path.join(static_folder, 'employer/images'),
    'jobseeker_files': os.path.join(static_folder, 'jobseeker/files_cv'),
    'jobseeker_images': os.path.join(static_folder, 'jobseeker/images'),
}

# Create directories
for folder in UPLOAD_FOLDERS.values():
    os.makedirs(folder, exist_ok=True)


# Utility function to validate file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    """ Set Up connection to database"""
    conn = sqlite3.connect('job_portal.db')
    conn.row_factory = sqlite3.Row
    return conn


# Route for the landing page
@app.route('/')
@app.route('/home')
@app.route('/index')
def landing_page():
    return render_template('landing_page.html')


@app.route('/employer_index')
def employer_index():
    """Employer dashboard displaying statistics for the logged-in employer."""
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash("Please log in as an employer to access this page.", "warning")
        return redirect(url_for('landing_page'))

    user_id = session['user_id']  # Get the logged-in employer's ID
    conn = get_db()

    try:
        # Fetch job statistics for the employer
        job_stats = conn.execute('''
            SELECT
                COUNT(*) AS total_jobs,
                SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active_jobs,
                SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS closed_jobs
            FROM Jobs
            WHERE employer_id = ?
        ''', (user_id,)).fetchone()

        # Fetch application statistics for jobs posted by the employer
        application_stats = conn.execute('''
            SELECT
                COUNT(*) AS total_applications,
                SUM(CASE WHEN application_status = 'Applied'
                THEN 1 ELSE 0 END) AS pending_review,
                SUM(CASE WHEN application_status = 'Rejected'
                THEN 1 ELSE 0 END) AS rejected,
                SUM(CASE WHEN application_status = 'Interview'
                THEN 1 ELSE 0 END) AS interviewed

            FROM Applications
            WHERE job_id IN (SELECT job_id FROM Jobs WHERE employer_id = ?)
        ''', (user_id,)).fetchone()

        # Default to 0 if no data is found
        job_stats = dict(job_stats) if job_stats else {
            "total_jobs": 0, "active_jobs": 0, "closed_jobs": 0}
        application_stats = dict(application_stats) if application_stats else {
            "total_applications": 0,
            "pending_review": 0,
            "interviewed": 0,
            "rejected": 0
        }

    except sqlite3.OperationalError:
        flash(
            "An error occurred while fetching statistics. Please try again later.", "danger")
        job_stats = {"total_jobs": 0, "active_jobs": 0, "closed_jobs": 0}
        application_stats = {"total_applications": 0,
                             "pending_review": 0, "rejected": 0, "interviewed": 0}

    finally:
        conn.close()

    return render_template('employer/employer_index.html',
                           job_stats=job_stats,
                           application_stats=application_stats)


# Route for the login page (dynamic for each user type)
@csrf.exempt
@app.route('/login/<user_type>', methods=['GET', 'POST'])
def login(user_type):
    # Redirect job seekers directly to job_seeker_index without login
    if user_type == 'job_seeker':
        return redirect(url_for('job_seeker_index'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM Users WHERE email = ? AND user_type = ?',
            (email, user_type)).fetchone()
        conn.close()

        # Check if a user with the provided email and user_type exists
        if not user:
            flash("Invalid email or user type.", "danger")
            return redirect(url_for('login', user_type=user_type))

        # Check if the entered password matches the stored hashed password
        if not bcrypt.check_password_hash(user['password'], password):
            flash("Invalid password.", "danger")
            return redirect(url_for('login', user_type=user_type))

        # Set user session details if login is successful
        session['user_id'] = user['user_id']
        session['user_type'] = user['user_type']

        # Redirect based on user type
        if user['user_type'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user['user_type'] == 'employer':
            return redirect(url_for('employer_index'))
        elif user['user_type'] == 'job_seeker':
            return redirect(url_for('job_seeker_index'))
        else:
            flash("Invalid user type.", "danger")
            return redirect(url_for('login', user_type=user_type))

    # If GET request or login fails, render the login page
    return render_template('login.html', user_type=user_type)


@csrf.exempt
@app.route('/jobseeker_login/<user_type>', methods=['GET', 'POST'])
def jobseeker_login(user_type):

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        user = conn.execute(
            'SELECT * FROM Users WHERE email = ? AND user_type = ?',
            (email, user_type)).fetchone()
        conn.close()

        # Check if a user with the provided email and user_type exists
        if not user:
            flash("Invalid email or user type.", "danger")
            return redirect(url_for('jobseeker_login', user_type='job_seeker'))

        # Check if the entered password matches the stored hashed password
        if not bcrypt.check_password_hash(user['password'], password):
            flash("Invalid password.", "danger")
            return redirect(url_for('jobseeker_login', user_type='job_seeker'))

        # Set user session details if login is successful
        session['user_id'] = user['user_id']
        session['user_type'] = user['user_type']

        if user['user_type'] == 'job_seeker':
            return redirect(url_for('job_seeker_index'))
        else:
            flash("Invalid user type.", "danger")
            return redirect(url_for('jobseeker_login', user_type='job_seeker'))

    # If GET request or login fails, render the login page
    return render_template('jobseeker/jobseeker_login.html',
                           user_type=user_type)


# Route for Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        # If not logged in as admin, redirect to landing page
        return redirect(url_for('landing_page'))

    # Connect to database
    conn = get_db()
    cursor = conn.cursor()

    # Get total job categories
    cursor.execute("SELECT COUNT(*) FROM JobCategories")
    job_categories = cursor.fetchone()[0]

    # Get total employers
    cursor.execute("SELECT COUNT(*) FROM EmployerProfiles")
    employers = cursor.fetchone()[0]

    # Get total job seekers
    cursor.execute("SELECT COUNT(*) FROM JobSeekerProfiles")
    job_seekers = cursor.fetchone()[0]

    # Get total jobs
    cursor.execute("SELECT COUNT(*) FROM Jobs")
    jobs = cursor.fetchone()[0]

    conn.close()  # Close the database connection

    # Pass the fetched data to the template
    return render_template('admin/admin_dashboard.html',
                           job_categories=job_categories,
                           employers=employers,
                           job_seekers=job_seekers,
                           jobs=jobs)


@csrf.exempt
@app.route('/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch admin details (user_type = 'admin')
    cursor.execute(
        '''SELECT email FROM Users WHERE user_id = ?
        AND user_type = 'admin' ''', (session['user_id'],))
    admin = cursor.fetchone()

    if not admin:
        flash("Admin profile not found.", "danger")
        # Redirect if no admin found
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        new_email = request.form['email'].strip()  # Remove extra spaces

        # Validate email field is not empty
        if not new_email:
            flash('Email field cannot be empty.', 'danger')
            return redirect(url_for('admin_profile'))

        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, new_email):
            flash('Invalid email format. Please provide a valid email.', 'danger')
            return redirect(url_for('admin_profile'))

        # Update admin email
        cursor.execute('''
            UPDATE Users
            SET email = ?
            WHERE user_id = ? AND user_type = 'admin'
        ''', (new_email, session['user_id']))
        conn.commit()

        flash('Email updated successfully!', 'success')
        return redirect(url_for('admin_profile'))

    conn.close()
    return render_template('admin/admin_profile.html', admin=admin)


@csrf.exempt
@app.route('/admin/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        conn = get_db()
        try:
            cursor = conn.cursor()

            # Fetch the admin's current password from the database
            cursor.execute('''
                SELECT password FROM Users 
                WHERE user_id = ? AND user_type = 'admin'
            ''', (session['user_id'],))
            stored_password = cursor.fetchone()

            # Validate current password
            if not stored_password or not bcrypt.check_password_hash(stored_password[0], current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('change_password'))

            # Check if the new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('change_password'))

            # Validate password complexity
            if len(new_password) < 6 or not re.search(r'[A-Za-z]', new_password) or not re.search(r'\d', new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                flash(
                    'Password must be at least 6 characters long, include letters, numbers, and special characters.', 'danger')
                return redirect(url_for('change_password'))

            # Update password and set updated_at timestamp
            hashed_password = bcrypt.generate_password_hash(
                new_password).decode('utf-8')
            updated_at = datetime.now()  # Current timestamp
            cursor.execute('''
                UPDATE Users
                SET password = ?, updated_at = ?
                WHERE user_id = ? AND user_type = 'admin'
            ''', (hashed_password, updated_at, session['user_id']))
            conn.commit()

            flash('Password changed successfully!', 'success')
            return redirect(url_for('admin_profile'))

        except Exception:
            flash('An error occurred. Please try again later.', 'danger')
            return redirect(url_for('change_password'))

        finally:
            conn.close()

    return render_template('admin/change_password.html')


@csrf.exempt
@app.route('/manage_job_categories', methods=['GET', 'POST'])
def manage_job_categories():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        category_name = request.form.get('category_name', '').strip()
        industry_id = request.form.get('industry_id')

        if action == 'add' and category_name and industry_id:
            cursor.execute('''
                INSERT INTO JobCategories (category_name, industry_id)
                VALUES (?, ?)
            ''', (category_name, industry_id))
            conn.commit()
            flash('Category added successfully', 'success')

        elif action == 'edit':
            category_id = request.form.get('category_id')
            if category_id and category_name and industry_id:
                cursor.execute('''
                    UPDATE JobCategories
                    SET category_name = ?, industry_id = ?
                    WHERE category_id = ?
                ''', (category_name, industry_id, category_id))
                conn.commit()
                flash('Category updated successfully', 'success')

        else:
            flash('Invalid action or missing data.', 'danger')

        return redirect(url_for('manage_job_categories'))

    # Update the query to include the industry name
    cursor.execute('''
        SELECT jc.category_id, jc.category_name, i.industry_name
        FROM JobCategories jc
        LEFT JOIN Industries i ON jc.industry_id = i.industry_id
    ''')
    categories = cursor.fetchall()

    cursor.execute('SELECT * FROM Industries')
    industries = cursor.fetchall()

    return render_template("admin/manage_job_categories.html",
                           categories=categories, industries=industries)


@csrf.exempt
@app.route('/manage_industries', methods=['GET', 'POST'])
def manage_industries():
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        industry_name = request.form.get('industry_name', '').strip()

        if action == 'add' and industry_name:
            cursor.execute(
                "INSERT INTO Industries (industry_name) VALUES (?)",
                (industry_name,))
            conn.commit()
            flash('Industry added successfully', 'success')

        elif action == 'edit':
            industry_id = request.form.get('industry_id')
            if industry_id and industry_name:
                cursor.execute("UPDATE Industries SET industry_name = ? WHERE industry_id = ?",
                               (industry_name, industry_id))
                conn.commit()
                flash('Industry updated successfully', 'success')

        else:
            flash('Invalid action or missing data.', 'danger')

        return redirect(url_for('manage_industries'))

    cursor.execute("SELECT * FROM Industries")
    industries = cursor.fetchall()

    return render_template("admin/manage_industries.html",
                           industries=industries)


@csrf.exempt
@app.route('/manage_job_posts', methods=['GET'])
def manage_job_posts():
    conn = get_db()
    cursor = conn.cursor()

    # Get pagination parameters from query string
    page = request.args.get('page', 1, type=int)  # Default page is 1
    # Default 10 items per page
    per_page = request.args.get('per_page', 10, type=int)
    offset = (page - 1) * per_page

    # Fetch total number of job posts
    cursor.execute('SELECT COUNT(*) AS total FROM Jobs')
    total_posts = cursor.fetchone()['total']

    # Fetch paginated job posts
    cursor.execute('''
        SELECT j.job_id, j.title, j.description,
        ep.company_name AS employer_name,
               jc.category_name, i.industry_name, j.location, j.salary_range
        FROM Jobs j
        LEFT JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
        LEFT JOIN JobCategories jc ON j.category_id = jc.category_id
        LEFT JOIN Industries i ON j.industry_id = i.industry_id
        LIMIT ? OFFSET ?
    ''', (per_page, offset))

    job_posts = cursor.fetchall()

    conn.close()

    # Calculate total pages
    total_pages = (total_posts + per_page - 1) // per_page

    return render_template('admin/manage_job_posts.html',
                           job_posts=job_posts,
                           page=page,
                           total_pages=total_pages,
                           per_page=per_page)


@csrf.exempt
@app.route('/update_job_post/<int:job_id>', methods=['GET', 'POST'])
def update_job_post(job_id):
    conn = get_db()
    cursor = conn.cursor()

    # Fetch job post details for the given job_id
    cursor.execute('''SELECT * FROM Jobs WHERE job_id = ?''', (job_id,))
    job = cursor.fetchone()

    if not job:
        flash('Job post not found', 'danger')
        return redirect(url_for('manage_job_posts'))

    # Format the posted_at field if it exists
    if job['posted_at']:
        try:
            job = dict(job)  # Convert sqlite3.Row to a dictionary
        except ValueError as e:
            flash(f"Error formatting posted_at field: {e}", "danger")
            job['posted_at'] = None

    # Fetch all employers for the dropdown
    cursor.execute('''SELECT user_id, company_name FROM EmployerProfiles''')
    employers = cursor.fetchall()

    # Fetch all job categories for the dropdown
    cursor.execute('''SELECT category_id, category_name FROM JobCategories''')
    categories = cursor.fetchall()

    # Fetch all industries for the dropdown
    cursor.execute('''SELECT industry_id, industry_name FROM Industries''')
    industries = cursor.fetchall()

    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        salary_range = request.form['salary_range']
        employer_id = request.form['employer_id']
        category_id = request.form['category_id']
        industry_id = request.form['industry_id']

        # Handle 'is_active' checkbox
        is_active = 1 if 'is_active' in request.form else 0

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Update the job post with all fields
            cursor.execute('''
                UPDATE Jobs
                SET title = ?, description = ?, location = ?, salary_range = ?,
                employer_id = ?,
                category_id = ?, industry_id = ?, is_active = ?
                WHERE job_id = ?
            ''', (title, description, location, salary_range, employer_id,
                  category_id, industry_id, is_active, job_id))
            conn.commit()

            flash('Job post updated successfully!', 'success')
            return redirect(url_for('manage_job_posts'))

        except Exception as e:
            flash(f'Error updating job post: {e}', 'danger')
            return redirect(url_for('update_job_post', job_id=job_id))
        finally:
            conn.close()

    return render_template(
        'admin/update_job_post.html',
        job=job,
        employers=employers,
        categories=categories,
        industries=industries
    )


@app.route('/delete_job_post/<int:job_id>', methods=['GET'])
def delete_job_post(job_id):
    conn = get_db()
    cursor = conn.cursor()

    # Delete the job post
    cursor.execute('''
        DELETE FROM Jobs WHERE job_id = ?
    ''', (job_id,))

    conn.commit()
    conn.close()
    flash('Job post deleted successfully!', 'success')
    return redirect(url_for('manage_job_posts'))


@csrf.exempt
@app.route('/add_new_job_post', methods=['GET', 'POST'])
def add_new_job_post():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch all employers for the dropdown
    cursor.execute('''SELECT user_id, company_name FROM EmployerProfiles''')
    employers = cursor.fetchall()

    # Fetch all job categories for the dropdown
    cursor.execute('''SELECT category_id, category_name FROM JobCategories''')
    categories = cursor.fetchall()

    # Fetch all industries for the dropdown
    cursor.execute('''SELECT industry_id, industry_name FROM Industries''')
    industries = cursor.fetchall()

    conn.close()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        full_description = request.form['full_description']
        location = request.form['location']
        salary_range = request.form['salary_range']
        employer_id = request.form['employer_id']
        category_id = request.form['category_id']
        job_type = request.form['job_type']
        min_education_level = request.form['min_education_level']
        experience_level = request.form['experience_level']

        # Handle 'is_active' checkbox
        is_active = 'is_active' in request.form

        # Fetch the industry_id for the selected category_id
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT industry_id FROM JobCategories WHERE category_id = ?
        ''', (category_id,))
        industry = cursor.fetchone()

        # If a valid industry is found, use its industry_id
        if industry:
            industry_id = industry['industry_id']
        else:
            flash('No industry found for the selected category', 'danger')
            return redirect(url_for('add_new_job_post'))

        # Insert new job post into the database
        cursor.execute('''
            INSERT INTO Jobs (title, description, full_description,
            location, salary_range, employer_id, category_id, industry_id,
            job_type, min_education_level, experience_level, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, full_description,
              location, salary_range, employer_id,
              category_id,
              industry_id, job_type, min_education_level,
              experience_level, is_active))
        conn.commit()
        conn.close()

        flash('New job post added successfully!', 'success')
        return redirect(url_for('manage_job_posts'))

    return render_template('admin/add_job_post.html',
                           employers=employers, categories=categories,
                           industries=industries)


@app.route('/view_job_details/<int:job_id>', methods=['GET'])
def view_job_details(job_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch job details
        cursor.execute('''
            SELECT j.job_id, j.title, j.description, j.full_description,
            j.job_type, j.min_education_level, j.experience_level,
            ep.company_name AS employer_name, jc.category_name,
            i.industry_name, j.location, j.salary_range, ep.website,
            ep.logo AS employer_logo, j.posted_at, j.is_active
            FROM Jobs j
            JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
            JOIN JobCategories jc ON j.category_id = jc.category_id
            JOIN Industries i ON j.industry_id = i.industry_id
            WHERE j.job_id = ?
        ''', (job_id,))
        job = cursor.fetchone()

        if job:
            # Convert the 'posted_at' field to a datetime object
            job = dict(job)  # Convert sqlite3.Row to a dictionary
            job['posted_at'] = datetime.strptime(
                job['posted_at'], '%Y-%m-%d %H:%M:%S') if job['posted_at'] else None

    except Exception as e:
        flash(f"Error fetching job details: {e}", "danger")
        job = None
    finally:
        conn.close()

    if job:
        return render_template('admin/view_job_details.html', job=job)
    else:
        return render_template('error.html', message="Job not found"), 404


@app.route('/view_employer_profile/<int:user_id>')
def view_employer_profile(user_id):
    conn = get_db()
    cursor = conn.cursor()

    # Fetch employer profile
    cursor.execute(
        '''SELECT * FROM EmployerProfiles WHERE user_id = ?''', (user_id,))
    employer = cursor.fetchone()

    conn.close()

    if employer:
        return render_template('admin/view_employer_profile.html',
                               employer=employer)
    else:
        return render_template('error.html', message="Employer not found"), 404


@app.route('/view_job_seeker_profile/<int:user_id>')
def view_job_seeker_profile(user_id):
    conn = get_db()
    cursor = conn.cursor()

    # Fetch job seeker profile
    cursor.execute(
        '''SELECT * FROM JobSeekerProfiles WHERE user_id = ?''', (user_id,))
    job_seeker = cursor.fetchone()

    conn.close()

    if job_seeker:
        return render_template('admin/view_job_seeker_profile.html',
                               job_seeker=job_seeker)
    else:
        return render_template('error.html', message="Job Seeker not found"),
    404


@app.route('/manage_applications', methods=['GET'])
def manage_applications():
    conn = get_db()
    cursor = conn.cursor()

    # Pagination parameters
    page = request.args.get('page', 1, type=int)  # Current page, default to 1
    # Items per page, default to 10
    per_page = request.args.get('per_page', 10, type=int)
    offset = (page - 1) * per_page

    # Fetch total number of applications
    cursor.execute('SELECT COUNT(*) AS total FROM Applications')
    total_applications = cursor.fetchone()['total']

    # Fetch paginated job applications with employer name and latest status
    cursor.execute('''
        SELECT
            a.application_id,
            js.desired_job_title AS job_title,
            js.first_name || ' ' || js.last_name AS job_seeker_name,
            (SELECT status
             FROM ApplicationStatusHistory
             WHERE application_id = a.application_id
             ORDER BY updated_at DESC
             LIMIT 1) AS latest_status,
            a.cv_file_path,
            js.user_id AS job_seeker_id,
            ep.company_name AS employer_name
        FROM Applications a
        JOIN JobSeekerProfiles js ON a.job_seeker_id = js.user_id
        JOIN Jobs j ON a.job_id = j.job_id
        JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
        ORDER BY a.application_id DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset))

    applications = cursor.fetchall()

    conn.close()

    # Calculate total pages
    total_pages = (total_applications + per_page - 1) // per_page

    return render_template('admin/manage_applications.html',
                           applications=applications,
                           page=page,
                           total_pages=total_pages,
                           per_page=per_page)


@app.route('/view_cv')
def view_cv():
    cv_file_path = request.args.get('cv_file_path')  # Fetch CV file path

    # Ensure the file path is safe
    if not cv_file_path:
        abort(400, "No CV file path provided.")

    # Define the folder where the CVs are stored
    # Path to CV folder in static
    cv_folder = os.path.join('static', 'jobseeker', 'files_cv')

    # Ensure the file exists in the directory to prevent path traversal attacks
    file_path = os.path.join(cv_folder, cv_file_path)

    if not os.path.isfile(file_path):
        abort(404, "CV not found.")

    # Return the CV file for download
    return send_from_directory(cv_folder, cv_file_path, as_attachment=True)


@csrf.exempt
@app.route('/update_application_status/<int:application_id>',
           methods=['GET', 'POST'])
def update_application_status(application_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        # Get the new status and remark from the form
        new_status = request.form['status']
        remark = request.form['remark']

        # Updated allowed statuses to match the ones used in your database
        allowed_statuses = ['Applied', 'Interview',
                            'Offer', 'Rejected', 'Scheduled Meeting']

        if new_status in allowed_statuses:
            try:
                # Update the application status and remark
                cursor.execute('''
                    UPDATE Applications
                    SET application_status = ?, remark = ?,
                    updated_at = CURRENT_TIMESTAMP
                    WHERE application_id = ?
                ''', (new_status, remark, application_id))

                cursor.execute('''
                    INSERT INTO ApplicationStatusHistory (application_id,
                    status, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (application_id, new_status))

                conn.commit()
                flash(f'Application status updated to {
                      new_status}!', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Error updating application status: {e}', 'danger')
        else:
            flash('Invalid status selection.', 'error')

        return redirect(url_for('manage_applications'))

    # Fetch the current application details
    cursor.execute('''
        SELECT a.application_id, j.desired_job_title,
               j.first_name || ' ' || j.last_name AS job_seeker_name,
               a.application_status, a.remark
        FROM Applications a
        JOIN JobSeekerProfiles j ON a.job_seeker_id = j.user_id
        JOIN Users u ON a.job_seeker_id = u.user_id
        WHERE a.application_id = ?
    ''', (application_id,))
    application = cursor.fetchone()

    conn.close()
    return render_template('admin/update_application_status.html',
                           application=application)


@app.route('/manage_users')
def manage_users():
    conn = get_db()
    cursor = conn.cursor()

    # Get pagination parameters from request arguments
    page = int(request.args.get('page', 1))  # Default to page 1
    # Default 10 users per page
    per_page = int(request.args.get('per_page', 5))
    offset = (page - 1) * per_page

    # Fetch total counts for pagination
    cursor.execute('''
        SELECT COUNT(*) AS total_users
        FROM Users
        WHERE user_type IN ('employer', 'job_seeker') AND is_deleted = 0
    ''')
    total_users = cursor.fetchone()['total_users']
    # Calculate total pages
    total_pages = (total_users + per_page - 1) // per_page

    cursor.execute('''
        SELECT u.user_id, u.email, u.user_type,
               e.company_name, e.location,
               j.desired_job_title
        FROM Users u
        LEFT JOIN EmployerProfiles e ON u.user_id = e.user_id
        LEFT JOIN JobSeekerProfiles j ON u.user_id = j.user_id
        WHERE u.user_type IN ('employer', 'job_seeker') AND u.is_deleted = 0
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    users = cursor.fetchall()

    conn.close()

    # Separate employers and job seekers
    employers = [user for user in users if user['user_type'] == 'employer']
    job_seekers = [user for user in users if user['user_type'] == 'job_seeker']

    return render_template(
        'admin/manage_users.html',
        employers=employers,
        job_seekers=job_seekers,
        page=page,
        total_pages=total_pages,
        per_page=per_page
    )


@csrf.exempt
@app.route('/add_employer', methods=['GET', 'POST'])
def add_employer():
    conn = get_db()

    # Fetch industries for dropdown
    try:
        with conn:
            industries = conn.execute('SELECT * FROM Industries').fetchall()
    except Exception as e:
        flash(f"Error fetching industries: {e}", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Collect form data
        form_data = {
            'company_name': request.form['company_name'],
            'location': request.form['location'],
            'contact_email': request.form['contact_email'],
            'industry': request.form['industry'],
            'company_size': request.form['company_size'],
            'description': request.form['description'],
            'established_year': request.form['established_year'],
            'website': request.form['website'],
            'contact_person': request.form['contact_person'],
            'contact_phone': request.form['contact_phone'],
        }

        # Validate required fields
        required_fields = ['company_name', 'location', 'contact_email',
                           'industry', 'contact_person', 'contact_phone']
        if not all(form_data[field] for field in required_fields):
            flash("Required fields are missing.", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE email = ?",
                       (form_data['contact_email'],))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("The email address already exists in the system.", "danger")
            conn.close()
            return render_template('admin/add_employer.html',
                                   industries=industries)

        # Validate established year
        try:
            established_year = int(form_data['established_year'])
            if established_year < 1900 or established_year > time.localtime().tm_year:
                flash("Established year is not valid.", "danger")
                return render_template('admin/add_employer.html',
                                       industries=industries)
        except ValueError:
            flash("Established year must be a number.", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

        # Handle logo upload
        logo = request.files.get('logo')
        if not logo:
            flash("No file selected.", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

        if not allowed_file(logo.filename):
            flash("Invalid file type. Only PNG, JPG, and JPEG are allowed.", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

        try:
            filename = secure_filename(logo.filename)
            timestamp = int(time.time())  # Use timestamp for unique filenames
            unique_filename = f"{timestamp}_{filename}"

            logo_path = os.path.join(
                UPLOAD_FOLDERS['employer_images'], unique_filename)
            logo.save(logo_path)
        except Exception as e:
            flash(f"Error uploading logo: {e}", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

        # Default hashed password for the employer
        default_password = bcrypt.generate_password_hash(
            'default123!').decode('utf-8')

        try:
            with conn:
                # Insert into Users table
                conn.execute('''
                    INSERT INTO Users (email, password, user_type)
                    VALUES (?, ?, 'employer')
                ''', (form_data['contact_email'], default_password))
                user_id = conn.execute(
                    'SELECT last_insert_rowid()').fetchone()[0]

                # Insert into EmployerProfiles table
                conn.execute('''
                    INSERT INTO EmployerProfiles (
                        user_id, company_name, industry, location, website,
                        company_size,
                        description, established_year, contact_person,
                        contact_email,
                        contact_phone, logo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, form_data['company_name'], form_data['industry'],
                    form_data['location'], form_data['website'],
                    form_data['company_size'],
                    form_data['description'], form_data['established_year'],
                    form_data['contact_person'], form_data['contact_email'],
                    form_data['contact_phone'], unique_filename
                ))

            flash('Employer added successfully!', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            # Clean up uploaded file if insertion fails
            file_path = os.path.join(
                UPLOAD_FOLDERS['employer_images'], unique_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
            flash(f"Error adding employer: {e}", "danger")
            return render_template('admin/add_employer.html',
                                   industries=industries)

    return render_template('admin/add_employer.html', industries=industries)


@csrf.exempt
@app.route('/edit_employer/<int:user_id>', methods=['GET', 'POST'])
def edit_employer(user_id):
    conn = get_db()

    try:
        with conn:
            industries = conn.execute('SELECT * FROM Industries').fetchall()
            employer = conn.execute(
                'SELECT * FROM EmployerProfiles WHERE user_id = ?',
                (user_id,)).fetchone()

        if not employer:
            flash("Employer not found.", "danger")
            return redirect(url_for('view_employers_job_seekers'))

        if request.method == 'POST':
            # Collect form data
            form_data = {
                'company_name': request.form['company_name'],
                'location': request.form['location'],
                'industry': request.form['industry'],
                'company_size': request.form['company_size'],
                'description': request.form['description'],
                'established_year': request.form['established_year'],
                'website': request.form['website'],
                'contact_person': request.form['contact_person'],
                'contact_email': request.form['contact_email'],
                'contact_phone': request.form['contact_phone'],
            }

            # Validate required fields
            required_fields = ['company_name', 'location', 'industry',
                               'contact_email', 'contact_person',
                               'contact_phone']
            if not all(form_data[field] for field in required_fields):
                flash("Required fields are missing.", "danger")
                return render_template('admin/edit_employer.html',
                                       employer=employer,
                                       industries=industries)

            # Validate established year
            try:
                established_year = int(form_data['established_year'])
                if established_year < 1900 or established_year > datetime.now().year:
                    flash("Established year is not valid.", "danger")
                    return render_template('admin/edit_employer.html',
                                           employer=employer,
                                           industries=industries)
            except ValueError:
                flash("Established year must be a number.", "danger")
                return render_template('admin/edit_employer.html',
                                       employer=employer,
                                       industries=industries)

            # Handle logo upload with unique timestamp
            logo = request.files.get('logo')
            logo_filename = employer['logo']
            if logo and allowed_file(logo.filename):
                try:
                    original_filename = secure_filename(logo.filename)
                    # Use timestamp for uniqueness
                    timestamp = int(time.time())
                    unique_filename = f"{timestamp}_{original_filename}"
                    logo_path = os.path.join(
                        UPLOAD_FOLDERS['employer_images'], unique_filename)
                    logo.save(logo_path)
                    logo_filename = unique_filename
                except Exception as e:
                    flash(f"Error uploading logo: {e}", "danger")
                    return render_template('admin/edit_employer.html',
                                           employer=employer,
                                           industries=industries)

            try:
                updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with conn:
                    conn.execute('''
                        UPDATE EmployerProfiles
                        SET company_name = ?, location = ?, industry = ?,
                        company_size = ?, description = ?,
                            established_year = ?, website = ?,
                            contact_person = ?, contact_email = ?,
                            contact_phone = ?, logo = ?, updated_at = ?
                        WHERE user_id = ?
                    ''', (
                        form_data['company_name'], form_data['location'],
                        form_data['industry'],
                        form_data['company_size'], form_data['description'],
                        form_data['established_year'],
                        form_data['website'], form_data['contact_person'],
                        form_data['contact_email'],
                        form_data['contact_phone'], logo_filename, updated_at,
                        user_id
                    ))

                flash('Employer updated successfully!', 'success')
                return redirect(url_for('manage_users'))
            except Exception as e:
                flash(f"Error updating employer: {e}", "danger")
                return render_template('admin/edit_employer.html',
                                       employer=employer,
                                       industries=industries)

    except Exception as e:
        flash(f"Error loading employer data: {e}", "danger")
        return redirect(url_for('manage_users'))
    finally:
        conn.close()

    return render_template('admin/edit_employer.html',
                           employer=employer, industries=industries)


@csrf.exempt
@app.route('/delete_employer/<int:user_id>', methods=['POST'])
def delete_employer(user_id):
    conn = get_db()
    try:
        with conn:
            # Check if the employer exists
            employer = conn.execute(
                'SELECT * FROM EmployerProfiles WHERE user_id = ?',
                (user_id,)).fetchone()
            if not employer:
                flash("Employer not found.", "danger")
                return redirect(url_for('view_employers_job_seekers'))

            # Delete employer from EmployerProfiles table
            conn.execute(
                'DELETE FROM EmployerProfiles WHERE user_id = ?', (user_id,))

            # Mark the user as deleted in the Users table
            conn.execute(
                'UPDATE Users SET is_deleted = 1 WHERE user_id = ?',
                (user_id,))

            # Deactivate all jobs posted by the employer in the Jobs table
            conn.execute(
                'UPDATE Jobs SET is_active = 0 WHERE employer_id = ?',
                (user_id,))

        flash("Employer and associated data deleted and updated successfully.", "success")
        return redirect(url_for('manage_users'))

    except Exception as e:
        flash(f"Error deleting employer: {e}", "danger")
        return redirect(url_for('manage_users'))


@csrf.exempt
@app.route('/report_by_date', methods=['GET', 'POST'])
def report_by_date():
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            # Extend the end_date to the end of the day (23:59:59)
            end_date = datetime.strptime(
                end_date, '%Y-%m-%d') + timedelta(days=1) - timedelta(seconds=1)
        except ValueError:
            flash('Invalid date format. Please enter valid dates.', 'danger')
            return redirect(url_for('report_by_date'))

        conn = get_db()
        cursor = conn.cursor()

        # SQL query to fetch job posts within the specified date range
        cursor.execute('''
            SELECT j.job_id, j.title, ep.company_name AS employer_name,
                   jc.category_name, i.industry_name,
                   j.location, j.salary_range, j.posted_at
            FROM Jobs j
            JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
            JOIN JobCategories jc ON j.category_id = jc.category_id
            JOIN Industries i ON j.industry_id = i.industry_id
            WHERE j.posted_at BETWEEN ? AND ?
        ''', (start_date, end_date))

        reports = cursor.fetchall()
        conn.close()

        if reports:
            return render_template('admin/admin_report_by_date.html',
                                   reports=reports)
        else:
            flash('No records found for the selected date range.', 'warning')
            return redirect(url_for('report_by_date'))

    return render_template('admin/admin_report_by_date.html')


@app.route('/employer_profile', methods=['GET'])
def employer_profile():
    """Display the employer's profile."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch employer profile with industry name and account email
        employer = conn.execute('''
            SELECT e.user_id, e.company_name, e.industry, e.location,
            e.website, e.company_size,
                   e.description, e.established_year,
                   e.contact_person, e.contact_email,
                   e.contact_phone, e.logo,
                   i.industry_name, u.email AS account_email
            FROM EmployerProfiles e
            LEFT JOIN Industries i ON e.industry = i.industry_id
            LEFT JOIN Users u ON e.user_id = u.user_id
            WHERE e.user_id = ?
        ''', (user_id,)).fetchone()

        # Check if employer exists
        if not employer:
            flash('Employer profile not found.', 'danger')
            return redirect(url_for('employer_index'))

        # Fetch all industries for the dropdown
        industries = conn.execute('SELECT * FROM Industries').fetchall()

    except Exception as e:
        flash(f"Error fetching employer profile: {e}", "danger")
        return redirect(url_for('employer_index'))
    finally:
        conn.close()

    return render_template('employer/employer_profile.html',
                           employer=employer, industries=industries)


@csrf.exempt
@app.route('/employer_edit_profile', methods=['POST'])
def employer_edit_profile():
    """Edit the employer's profile."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash('Please log in to edit your profile.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch the current employer profile
        employer = conn.execute('''
            SELECT * FROM EmployerProfiles WHERE user_id = ?
        ''', (user_id,)).fetchone()

        if not employer:
            flash('Employer profile not found.', 'danger')
            return redirect(url_for('employer_profile'))

        # Collect form data
        company_name = request.form.get(
            'company_name') or employer['company_name']
        industry = request.form.get('industry') or employer['industry']
        location = request.form.get('location') or employer['location']
        website = request.form.get('website') or employer['website']
        company_size = request.form.get(
            'company_size') or employer['company_size']
        established_year = request.form.get(
            'established_year') or employer['established_year']
        contact_person = request.form.get(
            'contact_person') or employer['contact_person']
        contact_email = request.form.get(
            'contact_email') or employer['contact_email']
        contact_phone = request.form.get(
            'contact_phone') or employer['contact_phone']
        description = request.form.get(
            'description') or employer['description']

        # Handle logo upload with unique timestamp
        logo = request.files.get('logo')
        logo_filename = employer['logo']  # Default to existing logo
        if logo and allowed_file(logo.filename):
            try:
                original_filename = secure_filename(logo.filename)
                # Use timestamp for unique filenames
                timestamp = int(time.time())
                unique_filename = f"{timestamp}_{original_filename}"
                logo_path = os.path.join(
                    UPLOAD_FOLDERS['employer_images'], unique_filename)
                logo.save(logo_path)
                logo_filename = unique_filename
            except Exception as e:
                flash(f"Error uploading logo: {e}", "danger")
                return redirect(url_for('employer_profile'))

        # Current timestamp for updated_at
        updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Update the database
        conn.execute('''
            UPDATE EmployerProfiles
            SET company_name = ?, industry = ?, location = ?, website = ?,
                company_size = ?, established_year = ?, contact_person = ?,
                contact_email = ?, contact_phone = ?, description = ?,
                logo = ?, updated_at = ?
            WHERE user_id = ?
        ''', (company_name, industry, location, website, company_size,
              established_year,
              contact_person, contact_email, contact_phone, description,
              logo_filename,
              updated_at, user_id))
        conn.commit()
        flash('Profile updated successfully!', 'success')

    except Exception as e:
        flash(f"Error updating profile: {e}", 'danger')

    finally:
        conn.close()

    return redirect(url_for('employer_profile'))


@app.route('/employer_settings', methods=['GET'])
def employer_settings():
    """Display the settings page for the employer."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash('Please log in to access settings.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch account email from the Users table
        user = conn.execute(
            'SELECT email FROM Users WHERE user_id = ?', (user_id,)).fetchone()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('employer_index'))

    except Exception as e:
        flash(f"Error fetching user details: {e}", 'danger')
        return redirect(url_for('employer_index'))
    finally:
        conn.close()

    return render_template('employer/employer_setting.html',
                           account_email=user['email'])


@csrf.exempt
@app.route('/update_account_email', methods=['POST'])
def update_account_email():
    """Update the employer's account email."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash('Please log in to update your email.', 'danger')
        return redirect(url_for('login'))

    new_email = request.form.get('new_email')
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    conn = get_db()
    try:
        # Validate the email format
        if not new_email or not re.match(email_regex, new_email):
            flash('Invalid email format. Please enter a valid email.', 'danger')
            return redirect(url_for('employer_settings'))

        # Update the email in the database
        conn.execute('UPDATE Users SET email = ? WHERE user_id = ?',
                     (new_email, user_id))
        conn.commit()
        flash('Account email updated successfully!', 'success')

    except Exception as e:
        flash(f"Error updating email: {e}", 'danger')

    finally:
        conn.close()

    return redirect(url_for('employer_settings'))


@csrf.exempt
@app.route('/change_account_password', methods=['POST'])
def change_account_password():
    """Change the employer's account password."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please log in to change your password.', 'danger')
        return redirect(url_for('login'))

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    conn = get_db()  # Use get_db() for the connection
    try:
        # Fetch the current password from the database
        user = conn.execute(
            'SELECT password FROM Users WHERE user_id = ?',
            (user_id,)).fetchone()

        if not user or not bcrypt.check_password_hash(user['password'],
                                                      current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('employer_settings'))

        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('employer_settings'))

        # Validate password strength
        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, new_password):
            flash('Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.', 'danger')
            return redirect(url_for('employer_settings'))

        # Update the password
        hashed_password = bcrypt.generate_password_hash(
            new_password).decode('utf-8')
        conn.execute('UPDATE Users SET password = ? WHERE user_id = ?',
                     (hashed_password, user_id))
        conn.commit()
        flash('Password updated successfully!', 'success')

    except Exception:
        flash(f"An error occurred while updating the password. Please try again later.", 'danger')

    finally:
        conn.close()

    return redirect(url_for('employer_settings'))


@csrf.exempt
@app.route('/employer_change_password', methods=['GET', 'POST'])
def employer_change_password():
    """Change the employer's password."""
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()

    if request.method == 'POST':
        current_password = request.form['currentPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        try:
            # Fetch current hashed password from the database
            user = conn.execute(
                "SELECT password FROM Users WHERE user_id = ? AND user_type = 'employer'",
                (user_id,)
            ).fetchone()

            # Validate current password
            if not user or not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('employer_change_password'))

            # Validate new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('employer_change_password'))

            # Validate password strength
            strong_password = re.compile(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
            )
            if not strong_password.match(new_password):
                flash(
                    'Password must be at least 8 characters long and include a mix of uppercase, lowercase, numbers, and symbols.',
                    'danger',
                )
                return redirect(url_for('employer_change_password'))

            # Update the password and set updated_at timestamp
            hashed_password = generate_password_hash(new_password)
            conn.execute(
                """
                UPDATE Users
                SET password = ?, updated_at = ?
                WHERE user_id = ? AND user_type = 'employer'
                """,
                (hashed_password, datetime.now(), user_id),
            )
            conn.commit()

            flash('Password updated successfully!', 'success')
            return redirect(url_for('employer_profile'))

        except Exception:
            flash(
                'An error occurred while changing the password. Please try again.', 'danger')
            return redirect(url_for('employer_change_password'))

        finally:
            conn.close()


@csrf.exempt
@app.route('/employer_post_jobs', methods=['GET', 'POST'])
def employer_post_jobs():
    """Allow the employer to post a new job."""
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login', user_type='employer'))

    user_id = session['user_id']  # Logged-in employer ID

    conn = get_db()

    # Validate user_id in EmployerProfiles
    employer = conn.execute(
        'SELECT * FROM EmployerProfiles WHERE user_id = ?', (user_id,)
    ).fetchone()

    if not employer:
        flash("Employer profile not found. Please contact support.", "danger")
        return redirect(url_for('employer_index'))

    # Fetch job categories and industries for the dropdown
    categories = conn.execute(
        'SELECT category_id, category_name FROM JobCategories').fetchall()
    industries = conn.execute(
        'SELECT industry_id, industry_name FROM Industries').fetchall()

    if request.method == 'POST':
        try:
            # Collect form data
            title = request.form['title']
            description = request.form['description']
            location = request.form['location']
            salary_range = request.form['salary_range']
            category_id = request.form['category_id']
            industry_id = request.form['industry_id']
            job_type = request.form['job_type']
            min_education_level = request.form['min_education_level']
            experience_level = request.form['experience_level']
            full_description = request.form['full_description']
            is_active = 1 if 'is_active' in request.form else 0

            # Insert new job post
            conn.execute('''
                INSERT INTO Jobs (
                    title, description, category_id, industry_id, location,
                    salary_range, employer_id,
                    job_type, min_education_level, experience_level,
                    full_description, is_active, posted_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                title, description, category_id, industry_id, location,
                salary_range, user_id,
                job_type, min_education_level, experience_level,
                full_description, is_active,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))

            conn.commit()
            flash('Job post created successfully!', 'success')
            return redirect(url_for('manage_job_post_employer'))

        except Exception as e:
            flash(f'An error occurred while posting the job: {e}', 'danger')

        finally:
            conn.close()

    return render_template(
        'employer/employer_post_jobs.html',
        categories=categories,
        industries=industries
    )


@csrf.exempt
@app.route('/employer_edit_job_posts/<int:job_id>', methods=['GET', 'POST'])
def employer_edit_job_posts(job_id):
    """Edit a job post created by the employer."""
    # Ensure the user is logged in and is an employer
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash("Please log in to access this page.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()

    # Fetch job details
    job = conn.execute(
        'SELECT * FROM Jobs WHERE job_id = ? AND employer_id = ?',
        (job_id, user_id)
    ).fetchone()

    if not job:
        flash("Job not found or you don't have permission to edit it.", "danger")
        return redirect(url_for('manage_job_post_employer'))

    # Fetch job categories and industries for the dropdown
    categories = conn.execute(
        'SELECT category_id, category_name FROM JobCategories'
    ).fetchall()
    industries = conn.execute(
        'SELECT industry_id, industry_name FROM Industries'
    ).fetchall()

    if request.method == 'POST':
        try:
            # Collect form data or fallback to old values
            title = request.form.get('title') or job['title']
            description = request.form.get('description') or job['description']
            location = request.form.get('location') or job['location']
            salary_range = request.form.get('salary_range') or job['salary_range']
            category_id = request.form.get('category_id') or job['category_id']
            industry_id = request.form.get('industry_id') or job['industry_id']
            job_type = request.form.get('job_type') or job['job_type']
            min_education_level = request.form.get('min_education_level') or job['min_education_level']
            experience_level = request.form.get('experience_level') or job['experience_level']
            full_description = request.form.get('full_description') or job['full_description']

            # Properly handle checkbox for job status
            is_active = 1 if request.form.get('is_active') else 0

            # Update the job post in the database
            conn.execute('''
                UPDATE Jobs
                SET title = ?, description = ?, category_id = ?, industry_id = ?,
                    location = ?, salary_range = ?, job_type = ?, min_education_level = ?,
                    experience_level = ?, full_description = ?, is_active = ?
                WHERE job_id = ? AND employer_id = ?
            ''', (
                title, description, category_id, industry_id, location,
                salary_range, job_type, min_education_level, experience_level,
                full_description, is_active, job_id, user_id
            ))

            conn.commit()
            flash('Job post updated successfully!', 'success')
            return redirect(url_for('manage_job_post_employer'))

        except Exception as e:
            flash(f'An error occurred while updating the job: {e}', 'danger')

        finally:
            conn.close()

    return render_template(
        'employer/employer_edit_job_posts.html',
        job=job,
        categories=categories,
        industries=industries
    )


@app.route('/manage_job_post_employer', methods=['GET'])
def manage_job_post_employer():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your job posts.", "warning")
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch job posts for the logged-in employer
        job_posts = conn.execute('''
            SELECT job_id, title, location, salary_range, posted_at, is_active
            FROM Jobs
            WHERE employer_id = ?
        ''', (user_id,)).fetchall()

        # Convert rows to dicts and parse created_at as datetime
        job_posts = [
            {
                **dict(job),
                "posted_at": datetime.strptime(job["posted_at"], '%Y-%m-%d %H:%M:%S') if job["posted_at"] else None
            }
            for job in job_posts
        ]

    except Exception:
        flash("An error occurred while fetching job posts.", "danger")
        job_posts = []

    finally:
        conn.close()

    return render_template('employer/manage_job_posts.html',
                           job_posts=job_posts)


@app.route('/employer_view_job_details/<int:job_id>', methods=['GET'])
def employer_view_job_details(job_id):
    """View detailed information about a specific job post."""
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Fetch job details along with related industry, category, and employer logo
        job = cursor.execute('''
            SELECT
                j.job_id, j.title, j.description, j.full_description,
                j.location,
                j.salary_range, j.is_active, j.posted_at, j.job_type,
                j.min_education_level,
                j.experience_level, ep.company_name, ep.logo,
                jc.category_name, i.industry_name
            FROM Jobs j
            JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
            JOIN JobCategories jc ON j.category_id = jc.category_id
            JOIN Industries i ON j.industry_id = i.industry_id
            WHERE j.job_id = ?
        ''', (job_id,)).fetchone()

    except Exception as e:
        flash("An error occurred while fetching job details.", "danger")
        print(f"Error: {e}")  # Log the error for debugging
        return redirect(url_for('manage_job_post_employer'))

    finally:
        conn.close()

    if job:
        return render_template('employer/employer_view_job_details.html',
                               job=job)
    else:
        flash('Job post not found.', 'danger')
        return redirect(url_for('manage_job_post_employer'))


@app.route('/employer_view_job_seeker_profile/<int:job_seeker_id>',
           methods=['GET'])
def employer_view_job_seeker_profile(job_seeker_id):
    """View a specific job seeker's profile."""
    conn = get_db()
    try:
        # Fetch job seeker profile details
        job_seeker = conn.execute('''
            SELECT
                js.first_name,
                js.last_name,
                js.contact_email,
                js.contact_phone,
                js.profile_picture,
                js.cv_file AS cv_file,
                js.bio,
                js.skills,
                js.experience_years,
                js.education,
                js.location,
                js.linkedin_url,
                js.portfolio_url,
                js.desired_job_title,
                js.cover_letter,
                js.created_at,
                js.updated_at
            FROM JobSeekerProfiles js
            WHERE js.user_id = ?
        ''', (job_seeker_id,)).fetchone()

        if not job_seeker:
            flash("Job seeker profile not found.", "danger")
            return redirect(url_for('employer_manage_applications'))

        # Parse skills and format job seeker data
        job_seeker = dict(job_seeker)
        job_seeker['skills'] = job_seeker['skills'].split(
            ',') if job_seeker['skills'] else []

    except Exception as e:
        flash(f"An error occurred while retrieving the job seeker profile: {
              e}", "danger")
        return redirect(url_for('employer_manage_applications'))

    finally:
        conn.close()

    return render_template('employer/employer_view_job_seeker.html',
                           job_seeker=job_seeker)


@app.route('/normal_view_details/<int:job_seeker_id>', methods=['GET'])
def normal_view_details(job_seeker_id):
    """View a specific job seeker's profile."""
    conn = get_db()
    try:
        # Fetch job seeker profile details
        job_seeker = conn.execute('''
            SELECT
                js.first_name,
                js.last_name,
                js.contact_email,
                js.contact_phone,
                js.profile_picture,
                js.cv_file AS cv_file,
                js.bio,
                js.skills,
                js.experience_years,
                js.education,
                js.location,
                js.linkedin_url,
                js.portfolio_url,
                js.desired_job_title,
                js.cover_letter,
                js.created_at,
                js.updated_at
            FROM JobSeekerProfiles js
            WHERE js.user_id = ?
        ''', (job_seeker_id,)).fetchone()

        if not job_seeker:
            flash("Job seeker profile not found.", "danger")
            return redirect(url_for('employer_view_all_job_seeker'))

        # Parse skills and format job seeker data
        job_seeker = dict(job_seeker)
        job_seeker['skills'] = job_seeker['skills'].split(
            ',') if job_seeker['skills'] else []

    except Exception as e:
        flash(f"An error occurred while retrieving the job seeker profile: {
              e}", "danger")
        return redirect(url_for('employer_view_all_job_seeker'))

    finally:
        conn.close()

    return render_template('employer/normal_view_details.html',
                           job_seeker=job_seeker)



@app.route('/employer_manage_applications', methods=['GET'])
def employer_manage_applications():
    """View and manage job applications."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash("Please log in to manage applications.", "warning")
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch all applications for jobs posted by the employer
        applications = conn.execute('''
            SELECT
                a.application_id, a.application_status, a.remark,
                a.applied_at, a.job_seeker_id,
                js.first_name, js.last_name,
                js.contact_email AS applicant_email, js.contact_phone
                AS applicant_phone,
                j.title AS job_title, ep.company_name AS employer_name
            FROM Applications a
            JOIN JobSeekerProfiles js ON a.job_seeker_id = js.user_id
            JOIN Jobs j ON a.job_id = j.job_id
            JOIN EmployerProfiles ep ON j.employer_id = ep.user_id
            WHERE j.employer_id = ?
        ''', (user_id,)).fetchall()

        applications = [dict(app)
                        for app in applications]  # Convert rows to dicts

    except Exception:
        flash("An error occurred while fetching applications.", "danger")
        applications = []

    finally:
        conn.close()

    return render_template('employer/employer_manage_applications.html',
                           applications=applications)


@csrf.exempt
@app.route('/employer_update_application_status/<int:application_id>',
           methods=['GET', 'POST'])
def employer_update_application_status(application_id):
    """Update the status of a specific application."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash("Please log in to update application status.", "warning")
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch the application details
        application = conn.execute('''
            SELECT
                a.application_id, a.application_status, a.remark,
                js.first_name, js.last_name, js.contact_email,
                js.contact_phone,
                j.title AS job_title
            FROM Applications a
            JOIN JobSeekerProfiles js ON a.job_seeker_id = js.user_id
            JOIN Jobs j ON a.job_id = j.job_id
            WHERE a.application_id = ?
        ''', (application_id,)).fetchone()

        if not application:
            flash("Application not found.", "danger")
            return redirect(url_for('employer_manage_applications'))

        # Handle POST request to update status
        if request.method == 'POST':
            new_status = request.form.get('statusOptions')
            remarks = request.form.get('remarks')

            # Validate the new status
            if not new_status:
                flash("Please select a valid status.", "danger")
                return redirect(url_for('employer_update_application_status',
                                        application_id=application_id))

            # Update the application status in the database
            conn.execute('''
                UPDATE Applications
                SET application_status = ?, remark = ?, updated_at = ?
                WHERE application_id = ?
            ''', (new_status, remarks, datetime.now(), application_id))
            conn.commit()

            flash("Application status updated successfully.", "success")
            return redirect(url_for('employer_manage_applications'))
    except Exception:
        flash("An error occurred while updating application status.", "danger")
    finally:
        conn.close()

    return render_template('employer/employer_update_application_status.html',
                           application=application)


@app.route('/viewcv_employer/<int:job_seeker_id>', methods=['GET'])
def viewcv_employer(job_seeker_id):
    """Display the CV of a specific job seeker."""
    conn = get_db()
    try:
        # Fetch the CV file path for the job seeker
        job_seeker = conn.execute('''
            SELECT cv_file 
            FROM JobSeekerProfiles
            WHERE user_id = ?
        ''', (job_seeker_id,)).fetchone()

        if not job_seeker or not job_seeker['cv_file']:
            flash("CV not found for this job seeker.", "danger")
            return redirect(url_for('employer_manage_applications'))

        # Construct the file path
        cv_file_path = os.path.join(
            app.root_path, 'static/jobseeker/files_cv', job_seeker['cv_file'])

        # Check if the file exists
        if not os.path.exists(cv_file_path):
            flash("CV file does not exist.", "danger")
            return redirect(url_for('employer_manage_applications'))

        # Serve the CV file
        return send_file(cv_file_path, as_attachment=False)

    except Exception:
        flash("An error occurred while retrieving the CV.", "danger")
        return redirect(url_for('employer_manage_applications'))

    finally:
        conn.close()


@app.route('/employer_view_analytics', methods=['GET'])
def employer_view_analytics():
    """View analytics for job postings and applications."""
    user_id = session.get('user_id')  # Ensure the employer is logged in
    if not user_id:
        flash("Please log in to view analytics.", "warning")
        return redirect(url_for('login'))

    conn = get_db()
    try:
        # Fetch total job posts for the logged-in employer
        total_job_posts = conn.execute('''
            SELECT COUNT(*) AS total_jobs
            FROM Jobs
            WHERE employer_id = ?
        ''', (user_id,)).fetchone()['total_jobs']

        # Fetch total applications for the employer's jobs
        total_applications = conn.execute('''
            SELECT COUNT(*) AS total_apps
            FROM Applications a
            JOIN Jobs j ON a.job_id = j.job_id
            WHERE j.employer_id = ?
        ''', (user_id,)).fetchone()['total_apps']

        # Fetch the number of candidates in the interview stage
        interview_candidates = conn.execute('''
            SELECT COUNT(*) AS interview_count
            FROM Applications a
            JOIN Jobs j ON a.job_id = j.job_id
            WHERE j.employer_id = ? AND a.application_status = 'Interview'
        ''', (user_id,)).fetchone()['interview_count']

        # Fetch data for the "Applications by Job Post" chart
        applications_by_job = conn.execute('''
            SELECT j.title, COUNT(a.application_id) AS application_count
            FROM Jobs j
            LEFT JOIN Applications a ON j.job_id = a.job_id
            WHERE j.employer_id = ?
            GROUP BY j.job_id, j.title
        ''', (user_id,)).fetchall()

        # Prepare chart data
        chart_labels = [job['title'] for job in applications_by_job]
        chart_data = [job['application_count'] for job in applications_by_job]

    except Exception:
        flash("An error occurred while fetching analytics.", "danger")
        return redirect(url_for('employer_index'))

    finally:
        conn.close()

    return render_template('employer/employer_view_analytics.html',
                           total_job_posts=total_job_posts,
                           total_applications=total_applications,
                           interview_candidates=interview_candidates,
                           chart_labels=chart_labels,
                           chart_data=chart_data)


@app.route('/employer_messenger', methods=['GET'])
def employer_messenger():
    """Messenger for Employers."""
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash("Please log in as an employer to access the messenger.", "warning")
        return redirect(url_for('login', user_type='employer'))

    employer_id = session['user_id']
    conn = get_db()

    try:
        # Fetch all threads associated with the employer
        contacts_query = '''
            SELECT t.thread_id, 
                   jp.first_name || ' ' || jp.last_name AS name
            FROM Threads t
            JOIN JobSeekerProfiles jp ON t.job_seeker_id = jp.user_id
            WHERE t.employer_id = ?
        '''
        contacts = conn.execute(contacts_query, (employer_id,)).fetchall()
    except Exception as e:
        flash(f"Failed to fetch contacts: {e}", "danger")
        contacts = []
    finally:
        conn.close()

    return render_template('employer/employer_messenger.html',
                           contacts=contacts)


@app.route('/job_seeker_messenger', methods=['GET'])
def job_seeker_messenger():
    """Messenger for Job Seekers."""
    if 'user_id' not in session or session.get('user_type') != 'job_seeker':
        flash("Please log in to access the messenger.", "warning")
        return redirect(url_for('login', user_type='job_seeker'))

    job_seeker_id = session['user_id']
    conn = get_db()

    try:
        # Fetch threads for the job seeker
        contacts_query = '''
            SELECT t.thread_id, 
                   e.company_name AS name
            FROM Threads t
            JOIN EmployerProfiles e ON t.employer_id = e.user_id
            WHERE t.job_seeker_id = ?
        '''
        contacts = conn.execute(contacts_query, (job_seeker_id,)).fetchall()
    except Exception as e:
        flash(f"Failed to fetch contacts: {e}", "danger")
        contacts = []
    finally:
        conn.close()

    return render_template('jobseeker/jobseeker_messenger.html',
                           contacts=contacts)


@app.route('/view_thread/<int:thread_id>', methods=['GET'])
def view_thread(thread_id):
    """View messages in a thread for Employers."""
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash("Please log in to view this thread.", "warning")
        return redirect(url_for('login', user_type='employer'))

    employer_id = session['user_id']
    conn = get_db()

    try:
        # Validate thread access
        thread = conn.execute('''
            SELECT * FROM Threads WHERE thread_id = ? AND employer_id = ?
        ''', (thread_id, employer_id)).fetchone()

        if not thread:
            flash("You don't have access to this thread.", "danger")
            return redirect(url_for('employer_messenger'))

        # Fetch contacts
        contacts_query = '''
            SELECT t.thread_id,
                   jp.first_name || ' ' || jp.last_name AS name
            FROM Threads t
            JOIN JobSeekerProfiles jp ON t.job_seeker_id = jp.user_id
            WHERE t.employer_id = ?
        '''
        contacts = conn.execute(contacts_query, (employer_id,)).fetchall()

        # Fetch messages
        messages_query = '''
            SELECT
                m.sender_id,
                m.content,
                m.sent_at,
                jp.first_name || ' ' || jp.last_name AS sender_name
            FROM Messages m
            LEFT JOIN JobSeekerProfiles jp ON m.sender_id = jp.user_id
            WHERE m.thread_id = ?
            ORDER BY m.sent_at ASC
        '''
        messages = conn.execute(messages_query, (thread_id,)).fetchall()

        # Format messages
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                "sender_id": msg["sender_id"],
                "content": msg["content"],
                "sent_at": datetime.fromisoformat(msg["sent_at"]).strftime('%b %d, %Y %I:%M %p') if msg["sent_at"] else "",
                "sender_name": msg["sender_name"]
            })

        # Receiver (Job Seeker)
        receiver_id = thread['job_seeker_id']

    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        formatted_messages = []
        contacts = []
        receiver_id = None
    finally:
        conn.close()

    return render_template(
        'employer/employer_messenger.html',
        messages=formatted_messages,
        thread_id=thread_id,
        receiver_id=receiver_id,
        contacts=contacts
    )


@app.route('/view_thread_job_seeker/<int:thread_id>', methods=['GET'])
def view_thread_job_seeker(thread_id):
    """View messages in a thread for Job Seekers."""
    if 'user_id' not in session or session.get('user_type') != 'job_seeker':
        flash("Please log in to view this thread.", "warning")
        return redirect(url_for('login', user_type='job_seeker'))

    job_seeker_id = session['user_id']
    conn = get_db()

    try:
        # Validate thread access
        thread = conn.execute('''
            SELECT * FROM Threads WHERE thread_id = ? AND job_seeker_id = ?
        ''', (thread_id, job_seeker_id)).fetchone()

        if not thread:
            flash("You don't have access to this thread.", "danger")
            return redirect(url_for('job_seeker_messenger'))

        # Fetch contacts
        contacts_query = '''
            SELECT t.thread_id,
                   e.company_name AS name
            FROM Threads t
            JOIN EmployerProfiles e ON t.employer_id = e.user_id
            WHERE t.job_seeker_id = ?
        '''
        contacts = conn.execute(contacts_query, (job_seeker_id,)).fetchall()

        # Fetch messages
        messages_query = '''
            SELECT
                m.sender_id,
                m.content,
                m.sent_at,
                ep.company_name AS sender_name
            FROM Messages m
            LEFT JOIN EmployerProfiles ep ON m.sender_id = ep.user_id
            WHERE m.thread_id = ?
            ORDER BY m.sent_at ASC
        '''
        messages = conn.execute(messages_query, (thread_id,)).fetchall()

        # Format messages
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                "sender_id": msg["sender_id"],
                "content": msg["content"],
                "sent_at": datetime.fromisoformat(msg["sent_at"]).strftime('%b %d, %Y %I:%M %p') if msg["sent_at"] else "",
                "sender_name": msg["sender_name"]
            })

        # Receiver (Employer)
        receiver_id = thread['employer_id']

    except Exception as e:
        flash(f"An error occurred: {e}", "danger")
        formatted_messages = []
        contacts = []
        receiver_id = None
    finally:
        conn.close()

    return render_template(
        'jobseeker/jobseeker_messenger.html',
        messages=formatted_messages,
        thread_id=thread_id,
        receiver_id=receiver_id,
        contacts=contacts
    )


@app.route('/send_message', methods=['POST'])
def send_message():
    """Send a message in a thread."""
    if 'user_id' not in session:
        flash("Please log in to send a message.", "warning")
        return redirect(url_for('login'))

    sender_id = session['user_id']
    thread_id = request.form.get('thread_id')
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')

    # Basic validation
    if not thread_id or not receiver_id or not content.strip():
        flash("Invalid input. Please ensure all fields are filled out.", "danger")
        return redirect(request.referrer)

    conn = get_db()
    try:
        # Ensure sender_id is valid (to prevent issues)
        sender_type = session.get('user_type')
        if not sender_type:
            flash("Invalid sender type.", "danger")
            return redirect(request.referrer)

        # Insert the message into the Messages table
        sent_at = datetime.now()
        conn.execute('''
            INSERT INTO Messages (thread_id, sender_id, receiver_id, content, sent_at) 
            VALUES (?, ?, ?, ?, ?)
        ''', (thread_id, sender_id, receiver_id, content.strip(), sent_at))

        # Determine notification message
        if sender_type == 'employer':
            company_name_query = '''
                SELECT company_name
                FROM EmployerProfiles
                WHERE user_id = ?
            '''
            company_name = conn.execute(
                company_name_query, (sender_id,)).fetchone()
            if company_name:
                notification_message = f"{company_name['company_name']} sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
            else:
                notification_message = f"An employer sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
        elif sender_type == 'job_seeker':
            job_seeker_name_query = '''
                SELECT first_name || ' ' || last_name AS full_name
                FROM JobSeekerProfiles
                WHERE user_id = ?
            '''
            job_seeker_name = conn.execute(
                job_seeker_name_query, (sender_id,)).fetchone()
            if job_seeker_name:
                notification_message = f"{job_seeker_name['full_name']} sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
            else:
                notification_message = f"A job seeker sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
        else:
            notification_message = f"You received a new message at {
                sent_at.strftime('%I:%M %p on %B %d, %Y')}."

        # Insert the notification with thread_id
        conn.execute('''
            INSERT INTO Notifications (user_id, title, message, created_at,
            thread_id, is_read)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (receiver_id, "New Message",
              notification_message, sent_at, thread_id))

        # Commit the transaction
        conn.commit()
        flash("Message sent successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to send message: {e}", "danger")
    finally:
        conn.close()

    return redirect(request.referrer)


@app.route('/start_conversation', methods=['POST'])
def start_conversation():
    """Start a conversation and optionally send an initial message."""
    if 'user_id' not in session:
        flash("Please log in to start a conversation.", "warning")
        return redirect(url_for('login', user_type='employer'))

    employer_id = session['user_id']
    job_seeker_id = request.form.get('job_seeker_id')
    initial_message = "Hi, I would like to start a conversation."

    if not job_seeker_id:
        flash("Invalid job seeker.", "danger")
        return redirect(request.referrer)

    conn = get_db()

    try:
        # Check if a thread already exists
        existing_thread = conn.execute('''
            SELECT thread_id FROM Threads
            WHERE employer_id = ? AND job_seeker_id = ? AND is_active = 1
        ''', (employer_id, job_seeker_id)).fetchone()

        if existing_thread:
            flash("Conversation already exists.", "info")
            return redirect(url_for('view_thread',
                                    thread_id=existing_thread['thread_id']))

        # Create a new thread
        conn.execute('''
            INSERT INTO Threads (employer_id, job_seeker_id, is_active)
            VALUES (?, ?, 1)
        ''', (employer_id, job_seeker_id))
        conn.commit()

        # Fetch the newly created thread ID
        thread_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

        # Insert the initial message
        conn.execute('''
            INSERT INTO Messages (thread_id, sender_id, receiver_id,
            content, sent_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (thread_id, employer_id, job_seeker_id,
              initial_message, datetime.now()))

        sender_type = session.get('user_type')
        sent_at = datetime.now()
        if sender_type == 'employer':
            company_name_query = '''
                SELECT company_name
                FROM EmployerProfiles
                WHERE user_id = ?
            '''
            company_name = conn.execute(
                company_name_query, (employer_id,)).fetchone()
            if company_name:
                notification_message = f"{company_name['company_name']} started a conversation with you at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
            else:
                notification_message = f"An employer started a conversation with you at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
        elif sender_type == 'job_seeker':
            job_seeker_name_query = '''
                SELECT first_name || ' ' || last_name AS full_name
                FROM JobSeekerProfiles
                WHERE user_id = ?
            '''
            job_seeker_name = conn.execute(
                job_seeker_name_query, (employer_id,)).fetchone()
            if job_seeker_name:
                notification_message = f"{job_seeker_name['full_name']} started a conversation with you at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
            else:
                notification_message = f"A job seeker started a conversation with you at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
        else:
            notification_message = f"You have a new conversation started at {
                sent_at.strftime('%I:%M %p on %B %d, %Y')}."

        # Add a notification for the job seeker with the thread_id
        conn.execute('''
            INSERT INTO Notifications (user_id, title, message, created_at,
            thread_id, is_read)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (job_seeker_id, "New Conversation",
              notification_message, sent_at, thread_id))

        conn.commit()

        flash("Conversation started successfully.", "success")
        return redirect(url_for('view_thread', thread_id=thread_id))

    except Exception as e:
        flash(f"Failed to start conversation: {e}", "danger")
        return redirect(request.referrer)

    finally:
        conn.close()


@app.route('/send_message_job_seeker', methods=['POST', 'GET'])
def send_message_job_seeker():
    """Send a message in a thread for Job Seekers"""
    if 'user_id' not in session or session.get('user_type') != 'job_seeker':
        flash("Please log in to send a message.", "warning")
        return redirect(url_for('login', user_type='job_seeker'))

    # Retrieve data from the form
    sender_id = session['user_id']
    thread_id = request.form.get('thread_id')
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')

    # Validate inputs
    if not thread_id or not receiver_id:
        flash("Invalid thread or receiver.", "danger")
        return redirect(request.referrer)

    if not content.strip():
        flash("Message cannot be empty.", "danger")
        return redirect(request.referrer)

    conn = get_db()
    try:
        # Insert the message into the database
        sent_at = datetime.now()
        conn.execute('''
            INSERT INTO Messages (thread_id, sender_id,
            receiver_id, content, sent_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (thread_id, sender_id, receiver_id, content.strip(), sent_at))

        # Create a notification for the employer
        sender_type = session.get('user_type')
        if sender_type == 'job_seeker':
            job_seeker_name_query = '''
                SELECT first_name || ' ' || last_name AS full_name
                FROM JobSeekerProfiles
                WHERE user_id = ?
            '''
            job_seeker_name = conn.execute(
                job_seeker_name_query, (sender_id,)).fetchone()
            if job_seeker_name:
                notification_message = f"{job_seeker_name['full_name']} sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."
            else:
                notification_message = f"A job seeker sent you a message at {
                    sent_at.strftime('%I:%M %p on %B %d, %Y')}."

        # Add a notification for the employer with the thread_id
        conn.execute('''
            INSERT INTO Notifications (user_id, title, message, created_at,
            thread_id, is_read)
            VALUES (?, ?, ?, ?, ?, 0)
        ''', (receiver_id, "New Message", notification_message, sent_at,
              thread_id))

        conn.commit()
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash(f"Failed to send message: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for('view_thread_job_seeker', thread_id=thread_id))


@app.route('/notifications', methods=['GET'])
def get_notifications():
    user_id = session.get('user_id')  # Assumes user is logged in
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    # Fetch only unread notifications
    notifications = conn.execute(
        "SELECT * FROM Notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()

    return jsonify([dict(notification) for notification in notifications])


@csrf.exempt
# Reset notifications for the logged-in user
@app.route('/reset_notifications/<int:thread_id>', methods=['POST'])
def reset_notification(thread_id):
    user_id = session.get('user_id')  # Assumes user is logged in
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    conn.execute(
        "UPDATE Notifications SET is_read = 1 WHERE user_id = ? AND thread_id = ?",
        (user_id, thread_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@csrf.exempt
@app.route('/job_seeker_index', methods=['GET', 'POST'])
def job_seeker_index():

    conn = get_db()
    # Ensure the database returns rows as sqlite3.Row objects
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get the job seeker's profile
    user_logged_in = 'user_id' in session and session.get(
        'user_type') == 'job_seeker'
    job_seeker_id = session.get('user_id') if user_logged_in else None
    cursor.execute(
        'SELECT industry_id FROM JobSeekerProfiles WHERE user_id = ?',
        (job_seeker_id,))
    job_seeker = cursor.fetchone()

    # Fetch all industries
    cursor.execute('SELECT industry_id, industry_name FROM Industries')
    # Convert to list of dictionaries
    industries = [dict(row) for row in cursor.fetchall()]

    # Initialize jobs as empty
    jobs = []

    # Handle form submission for filtering jobs
    selected_industry_id = request.form.get('industry_id')
    if selected_industry_id:
        try:
            selected_industry_id = int(selected_industry_id)
            cursor.execute('''
                SELECT
                    Jobs.job_id, Jobs.title, Jobs.description, Jobs.location,
                    Jobs.salary_range,
                    COUNT(Applications.job_id) AS application_count,
                    EmployerProfiles.logo
                FROM Jobs
                LEFT JOIN Applications ON Jobs.job_id = Applications.job_id
                LEFT JOIN EmployerProfiles ON
                Jobs.employer_id = EmployerProfiles.user_id
                WHERE Jobs.is_active = 1 AND Jobs.industry_id = ?
                GROUP BY Jobs.job_id
                ORDER BY application_count DESC
                LIMIT 4
            ''', (selected_industry_id,))
            jobs = [dict(row) for row in cursor.fetchall()
                    ]  # Convert to list of dictionaries
        except ValueError:
            flash("Invalid industry selected.", "error")

    # Fetch the top 4 most applied jobs
    cursor.execute('''
        SELECT
            Jobs.job_id, Jobs.title, Jobs.description, Jobs.location,
            Jobs.salary_range,
            COUNT(Applications.job_id) AS application_count,
            EmployerProfiles.logo
        FROM Jobs
        LEFT JOIN Applications ON Jobs.job_id = Applications.job_id
        LEFT JOIN EmployerProfiles ON
        Jobs.employer_id = EmployerProfiles.user_id
        WHERE Jobs.is_active = 1
        GROUP BY Jobs.job_id
        ORDER BY application_count DESC
        LIMIT 4
    ''')
    trending_jobs = [dict(row) for row in cursor.fetchall()
                     ]  # Convert to list of dictionaries

    # Fetch partnership employer logos
    cursor.execute('''
        SELECT company_name, logo
        FROM EmployerProfiles
        WHERE logo IS NOT NULL
        LIMIT 5
    ''')
    partnership_employers = [
        # Convert to list of dictionaries
        dict(row) for row in cursor.fetchall()]

    conn.close()

    return render_template(
        'jobseeker/jobseeker_index.html',
        industries=industries,
        jobs=jobs,
        selected_industry_id=selected_industry_id,
        trending_jobs=trending_jobs,
        partnership_employers=partnership_employers
    )


@csrf.exempt
@app.route('/register', methods=['GET', 'POST'])
def register():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch industries for dropdown
    cursor.execute('SELECT industry_id, industry_name FROM Industries')
    industries = cursor.fetchall()

    if request.method == 'POST':
        # Collect form data
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        location = request.form.get('location', 'Not specified')
        desired_job_title = request.form.get('desired_job_title', 'Not specified')
        bio = request.form.get('bio', '')
        skills = request.form.get('skills', '')
        education = request.form.get('education', 'None')
        experience_years = request.form.get('experience_years', 0)
        linkedin_url = request.form.get('linkedin_url', '')
        portfolio_url = request.form.get('portfolio_url', '')
        contact_email = request.form['contact_email']
        contact_phone = request.form['contact_phone']
        industry_id = request.form.get('industry', None)
        cover_letter = request.form.get('cover_letter', '')
        cv_file = request.files.get('cv_file')

        # Email validation
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash("Invalid email address!", "error")
            return render_template('jobseeker/register.html', industries=industries)

        # Check if the email already exists
        cursor.execute('SELECT email FROM Users WHERE email = ?', (email,))
        existing_email = cursor.fetchone()
        if existing_email:
            flash("An account with this email address already exists.", "error")
            return render_template('jobseeker/register.html', industries=industries)

        # Validate passwords
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template('jobseeker/register.html', industries=industries)

        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash("Password must be at least 8 characters long, include letters, numbers, and special characters.", "error")
            return render_template('jobseeker/register.html', industries=industries)

        # Validate and save CV file
        if cv_file and allowed_file(cv_file.filename):
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            cv_filename = f"{timestamp}_{secure_filename(cv_file.filename)}"
            cv_file_path = os.path.join(UPLOAD_FOLDERS['jobseeker_files'], cv_filename)
            cv_file.save(cv_file_path)
        else:
            cv_filename = None  # Default to NULL for CV file

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            # Insert into Users table
            cursor.execute('''
                INSERT INTO Users (email, password, user_type)
                VALUES (?, ?, 'job_seeker')
            ''', (email, hashed_password))
            user_id = cursor.lastrowid

            # Insert into JobSeekerProfiles table
            cursor.execute('''
                INSERT INTO JobSeekerProfiles (
                    user_id, first_name, last_name, location,
                    desired_job_title, bio, skills, education,
                    experience_years, linkedin_url, portfolio_url,
                    contact_email, contact_phone, cv_file,
                    industry_id, cover_letter
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, first_name, last_name, location, desired_job_title, bio,
                  skills, education, experience_years, linkedin_url,
                  portfolio_url, contact_email, contact_phone, cv_filename, industry_id, cover_letter))

            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('jobseeker_login', user_type='job_seeker'))
        except sqlite3.IntegrityError as e:
            flash(f"An error occurred: {e}", "error")
        finally:
            conn.close()

    return render_template('jobseeker/register.html', industries=industries)


@csrf.exempt
@app.route('/jobs', methods=['GET', 'POST'])
def jobs():
    try:
        # Ensure the user is authenticated and authorized
        if 'user_id' not in session or session['user_type'] != 'job_seeker':
            return redirect(url_for('login'))

        # Connect to the database
        conn = get_db()
        cursor = conn.cursor()

        # Fetch job categories for filtering
        cursor.execute('SELECT category_id, category_name FROM JobCategories')
        categories = cursor.fetchall()

        # Fetch employer names and logos for filtering
        cursor.execute(
            'SELECT DISTINCT company_name, logo, user_id AS employer_id FROM EmployerProfiles')
        employers = cursor.fetchall()

        # Fetch job locations for filtering
        cursor.execute(
            'SELECT DISTINCT location FROM Jobs WHERE is_active = 1')
        locations = cursor.fetchall()

        selected_category = request.args.get(
            'category') or request.form.get('category')
        selected_employer = request.args.get(
            'employer') or request.form.get('employer')
        selected_location = request.args.get(
            'location') or request.form.get('location')
        search_query = request.args.get(
            'search') or request.form.get('search', '')
        date_filter = request.args.get(
            'date_filter') or request.form.get('date_filter')
        job_seeker_id = session['user_id']

        query = '''
        SELECT
            Jobs.job_id, Jobs.title, Jobs.description, Jobs.location,
            Jobs.salary_range, Jobs.job_type, EmployerProfiles.company_name,
            EmployerProfiles.logo, EmployerProfiles.user_id AS employer_id,
            Jobs.posted_at,
            (SELECT is_saved FROM job_saved
             WHERE job_saved.job_id = Jobs.job_id
             AND job_saved.job_seeker_id = ?) AS is_saved
        FROM Jobs
        LEFT JOIN EmployerProfiles ON
        Jobs.employer_id = EmployerProfiles.user_id
        WHERE Jobs.is_active = 1
        '''
        params = [job_seeker_id]

        # Apply filters
        if selected_category:
            query += ' AND Jobs.category_id = ?'
            params.append(selected_category)

        if selected_employer:
            query += ' AND EmployerProfiles.company_name = ?'
            params.append(selected_employer)

        if selected_location:
            query += ' AND Jobs.location = ?'
            params.append(selected_location)

        if search_query:
            query += ' AND Jobs.title LIKE ?'
            params.append(f'%{search_query}%')

        if date_filter:
            if date_filter == 'week':
                query += ' AND Jobs.posted_at >= DATE("now", "-7 days")'
            elif date_filter == 'month':
                query += ' AND Jobs.posted_at >= DATE("now", "-30 days")'

        # Execute query
        query += ' ORDER BY Jobs.posted_at DESC'
        cursor.execute(query, params)
        jobs = cursor.fetchall()

        conn.close()

        # Render the template
        return render_template(
            'jobseeker/jobs.html',
            jobs=jobs,
            categories=categories,
            employers=employers,
            locations=locations,
            selected_category=selected_category,
            selected_employer=selected_employer,
            selected_location=selected_location,
            search_query=search_query,
            date_filter=date_filter
        )
    except Exception:
        return "An error occurred. Please check the logs for more details.",
    500


@csrf.exempt
@app.route('/job/<int:job_id>', methods=['GET', 'POST'])
def job(job_id):
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job details
    cursor.execute('''
        SELECT
            Jobs.job_id,
            Jobs.title,
            Jobs.description,
            Jobs.location,
            Jobs.salary_range,
            Jobs.job_type,
            Jobs.full_description,
            Jobs.min_education_level,
            Jobs.experience_level,
            JobCategories.category_name,
            EmployerProfiles.company_name,
            EmployerProfiles.website,
            EmployerProfiles.logo
        FROM Jobs
        LEFT JOIN JobCategories ON Jobs.category_id = JobCategories.category_id
        LEFT JOIN EmployerProfiles ON
        Jobs.employer_id = EmployerProfiles.user_id
        WHERE Jobs.job_id = ?
    ''', (job_id,))
    job = cursor.fetchone()

    if not job:
        conn.close()
        flash("Job not found!", "error")
        return redirect(url_for('jobs'))

    # Get the job seeker's profile
    job_seeker_id = session['user_id']
    cursor.execute(
        'SELECT * FROM JobSeekerProfiles WHERE user_id = ?', (job_seeker_id,))
    job_seeker_profile = cursor.fetchone()

    if not job_seeker_profile:
        conn.close()
        flash("Profile not found!", "error")
        return redirect(url_for('job_seeker_index'))

    # Handle "Apply Now" action
    if request.method == 'POST':
        # Use dictionary-style access
        cover_letter = job_seeker_profile['cover_letter']
        cv_file_path = job_seeker_profile['cv_file']

        # Check if the job seeker has already applied
        cursor.execute('''
            SELECT * FROM Applications WHERE job_id = ? AND job_seeker_id = ?
        ''', (job_id, job_seeker_id))
        existing_application = cursor.fetchone()

        if existing_application:
            flash("You have already applied for this job.", "warning")
        else:
            try:
                # Insert into Applications table
                cursor.execute('''
                    INSERT INTO Applications (job_id, job_seeker_id,
                    cover_letter, application_status, cv_file_path)
                    VALUES (?, ?, ?, 'Applied', ?)
                ''', (job_id, job_seeker_id, cover_letter, cv_file_path))
                conn.commit()
                flash("Application submitted successfully!", "success")
            except sqlite3.Error as e:
                flash(f"An error occurred: {e}", "danger")
            finally:
                conn.close()

        return redirect(url_for('jobs'))

    # Fetch recommended jobs based on the industry (limit to 5)
    industry_id = job_seeker_profile['industry_id']
    cursor.execute('''
            SELECT
                Jobs.job_id,
                Jobs.title,
                Jobs.description,
                Jobs.location,
                EmployerProfiles.logo,
                Jobs.salary_range
            FROM Jobs
            LEFT JOIN EmployerProfiles ON
            Jobs.employer_id = EmployerProfiles.user_id
            WHERE Jobs.is_active = 1 AND Jobs.industry_id = ?
            AND Jobs.job_id != ?
            LIMIT 5;
    ''', (industry_id, job_id))
    recommended_jobs = cursor.fetchall()

    conn.close()

    return render_template(
        'jobseeker/job_detail.html',
        job=dict(job),
        recommended_jobs=[dict(job) for job in recommended_jobs]
    )


@csrf.exempt
@app.route('/apply/<int:job_id>', methods=['GET', 'POST'])
def apply(job_id):
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job seeker profile along with industry
    job_seeker_id = session['user_id']
    cursor.execute('''
        SELECT jsp.first_name, jsp.last_name, jsp.contact_email, jsp.location,
               jsp.desired_job_title, jsp.bio, jsp.skills, jsp.education,
               jsp.experience_years, jsp.linkedin_url, jsp.portfolio_url,
               jsp.cover_letter, jsp.cv_file, ind.industry_name
        FROM JobSeekerProfiles jsp
        LEFT JOIN Industries ind ON jsp.industry_id = ind.industry_id
        WHERE jsp.user_id = ?
    ''', (job_seeker_id,))
    job_seeker_profile = cursor.fetchone()

    if not job_seeker_profile:
        flash("Profile not found!", "error")
        return redirect(url_for('jobs'))

    if request.method == 'POST':
        # Handle "Apply Now" action
        cover_letter = request.form.get('cover_letter')
        cv_file_path = job_seeker_profile['cv_file']

        # Check if the job seeker has already applied for this job
        cursor.execute('''
            SELECT * FROM Applications WHERE job_id = ? AND job_seeker_id = ?
        ''', (job_id, job_seeker_id))
        existing_application = cursor.fetchone()

        if existing_application:
            flash("You have already applied for this job.", "warning")
        else:
            try:
                # Insert application into Applications table
                cursor.execute('''
                    INSERT INTO Applications (job_id, job_seeker_id,
                    cover_letter, application_status, cv_file_path)
                    VALUES (?, ?, ?, 'Applied', ?)
                ''', (job_id, job_seeker_id, cover_letter, cv_file_path))
                conn.commit()
                flash("Application submitted successfully!", "success")
            except sqlite3.Error as e:
                flash(f"An error occurred: {e}", "danger")
            finally:
                conn.close()

        return redirect(url_for('jobs'))

    conn.close()
    return render_template('jobseeker/apply.html',
                           job_seeker_profile=job_seeker_profile,
                           job_id=job_id)


@csrf.exempt
@app.route('/update_profile_apply/<int:job_id>', methods=['GET', 'POST'])
def update_profile_apply(job_id):
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job seeker profile
    job_seeker_id = session['user_id']
    cursor.execute(
        'SELECT * FROM JobSeekerProfiles WHERE user_id = ?', (job_seeker_id,))
    job_seeker_profile = cursor.fetchone()

    if not job_seeker_profile:
        flash("Profile not found!", "error")
        return redirect(url_for('jobs'))

    # Fetch industries
    cursor.execute('SELECT industry_id, industry_name FROM Industries')
    industries = cursor.fetchall()

    if request.method == 'POST':
        # Update job seeker profile
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        contact_email = request.form['contact_email']
        contact_phone = request.form['contact_phone']
        location = request.form['location']
        desired_job_title = request.form['desired_job_title']
        linkedin_url = request.form['linkedin_url']
        portfolio_url = request.form['portfolio_url']
        cover_letter = request.form['cover_letter']
        bio = request.form.get('bio', '')
        skills = request.form.get('skills', '')
        education = request.form.get('education', '')
        experience_years = request.form.get('experience_years', '')
        industry_id = request.form.get('industry')  # Capture industry selection

        # Handle new CV file upload
        cv_file = request.files.get('cv_file')
        cv_filename = job_seeker_profile['cv_file']

        if cv_file and allowed_file(cv_file.filename):
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            cv_filename = f"{timestamp}_{secure_filename(cv_file.filename)}"
            cv_folder = UPLOAD_FOLDERS['jobseeker_files']
            cv_file.save(os.path.join(cv_folder, cv_filename))

        try:
            cursor.execute('''
                UPDATE JobSeekerProfiles
                SET first_name = ?, last_name = ?, contact_email = ?,
                    contact_phone = ?, location = ?, desired_job_title = ?,
                    linkedin_url = ?, portfolio_url = ?, cover_letter = ?,
                    bio = ?, skills = ?, education = ?, experience_years = ?,
                    industry_id = ?, cv_file = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (first_name, last_name, contact_email, contact_phone, location,
                  desired_job_title, linkedin_url, portfolio_url, cover_letter,
                  bio, skills, education, experience_years, industry_id,
                  cv_filename, job_seeker_id))
            conn.commit()
            flash("Profile updated successfully!", "success")
        except sqlite3.Error as e:
            flash(f"An error occurred: {e}", "error")
        finally:
            conn.close()

        # Redirect back to the apply page
        return redirect(url_for('apply', job_id=job_id))

    conn.close()
    return render_template('jobseeker/update_profile_apply.html',
                           job_seeker_profile=job_seeker_profile,
                           industries=industries,
                           job_id=job_id)


@csrf.exempt
@app.route('/manage_profile_job_seeker', methods=['GET', 'POST'])
def manage_profile_job_seeker():
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job seeker profile
    job_seeker_id = session['user_id']
    cursor.execute(
        'SELECT * FROM JobSeekerProfiles WHERE user_id = ?', (job_seeker_id,))
    job_seeker_profile = cursor.fetchone()

    if not job_seeker_profile:
        flash("Profile not found!", "error")
        return redirect(url_for('job_seeker_index'))

    conn.close()
    return render_template('jobseeker/jobseekerprofile.html',
                           job_seeker_profile=job_seeker_profile)


@csrf.exempt
@app.route('/edit_profile_job_seeker', methods=['GET', 'POST'])
def edit_profile_job_seeker():
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job seeker profile
    job_seeker_id = session['user_id']
    cursor.execute(
        'SELECT * FROM JobSeekerProfiles WHERE user_id = ?', (job_seeker_id,))
    job_seeker_profile = cursor.fetchone()

    if not job_seeker_profile:
        flash("Profile not found!", "error")
        return redirect(url_for('manage_profile_job_seeker'))

    # Fetch industry options
    cursor.execute('SELECT industry_id, industry_name FROM Industries')
    industries = cursor.fetchall()

    if request.method == 'POST':
        # Update job seeker profile
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        contact_email = request.form['contact_email']
        contact_phone = request.form['contact_phone']
        location = request.form['location']
        desired_job_title = request.form['desired_job_title']
        cover_letter = request.form['cover_letter']
        linkedin_url = request.form['linkedin_url']
        portfolio_url = request.form['portfolio_url']
        bio = request.form.get('bio', '')
        skills = request.form.get('skills', '')
        education = request.form.get('education', '')
        experience_years = request.form.get('experience_years', '')
        industry_id = request.form.get('industry')  # Get selected industry ID

        # Handle new CV file upload
        cv_file = request.files.get('cv_file')
        cv_filename = job_seeker_profile['cv_file']

        if cv_file and allowed_file(cv_file.filename):
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            cv_filename = f"{timestamp}_{secure_filename(cv_file.filename)}"
            cv_folder = UPLOAD_FOLDERS['jobseeker_files']
            cv_file.save(os.path.join(cv_folder, cv_filename))

        # Handle new profile picture upload
        profile_picture = request.files.get('profile_picture')
        profile_picture_filename = job_seeker_profile['profile_picture']

        if profile_picture and allowed_file(profile_picture.filename):
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            profile_picture_filename = f"{timestamp}_{secure_filename(profile_picture.filename)}"
            profile_picture_folder = UPLOAD_FOLDERS['jobseeker_images']
            profile_picture.save(os.path.join(profile_picture_folder, profile_picture_filename))

        try:
            cursor.execute('''
                UPDATE JobSeekerProfiles
                SET first_name = ?, last_name = ?, contact_email = ?,
                    contact_phone = ?, location = ?, desired_job_title = ?,
                    linkedin_url = ?, portfolio_url = ?, bio = ?, cover_letter = ?,
                    skills = ?, education = ?, experience_years = ?, industry_id = ?,
                    cv_file = ?, profile_picture = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (first_name, last_name, contact_email, contact_phone, location,
                  desired_job_title, linkedin_url, portfolio_url, bio, cover_letter,
                  skills, education, experience_years, industry_id, cv_filename,
                  profile_picture_filename, job_seeker_id))
            conn.commit()
            flash("Profile updated successfully!", "success")
        except sqlite3.Error as e:
            flash(f"An error occurred: {e}", "error")
        finally:
            conn.close()

        return redirect(url_for('manage_profile_job_seeker'))

    conn.close()
    return render_template('jobseeker/jobseeker_edit_profile.html',
                           job_seeker_profile=job_seeker_profile,
                           industries=industries)


@csrf.exempt
@app.route('/change_password_job_seeker', methods=['GET', 'POST'])
def change_password_job_seeker():
    """Change the job seeker's password."""
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()

    if request.method == 'POST':
        current_password = request.form['currentPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']

        try:
            # Fetch the current hashed password from the database
            user = conn.execute(
                "SELECT password FROM Users WHERE user_id = ? AND user_type = 'job_seeker'",
                (user_id,)
            ).fetchone()

            # Validate the current password
            if not user or not bcrypt.check_password_hash(user['password'], current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('change_password_job_seeker'))

            # Validate new passwords match
            if new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('change_password_job_seeker'))

            # Validate password strength
            strong_password = re.compile(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
            )
            if not strong_password.match(new_password):
                flash(
                    'Password must be at least 8 characters long and include a mix of uppercase, lowercase, numbers, and symbols.',
                    'danger',
                )
                return redirect(url_for('change_password_job_seeker'))

            # Hash the new password and update it in the database
            hashed_password = bcrypt.generate_password_hash(
                new_password).decode('utf-8')

            conn.execute(
                """
                UPDATE Users
                SET password = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND user_type = 'job_seeker'
                """,
                (hashed_password, user_id),
            )
            conn.commit()

            flash('Password updated successfully!', 'success')
            return redirect(url_for('manage_profile_job_seeker'))

        except Exception:
            flash(
                'An error occurred while changing the password. Please try again.', 'danger')
            return redirect(url_for('change_password_job_seeker'))

        finally:
            conn.close()

    return render_template('jobseeker/jobseeker_changepassword.html')


@csrf.exempt
@app.route('/view_profile_job_seeker')
def view_profile_job_seeker():
    return render_template('view_profile.html')


@csrf.exempt
@app.route('/track_applications')
def track_applications():
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch applications for the logged-in job seeker
    job_seeker_id = session['user_id']
    cursor.execute('''
        SELECT 
            Applications.application_id,
            Applications.job_id,
            Applications.cover_letter,
            Applications.application_status,
            Applications.cv_file_path,
            Applications.applied_at,
            Jobs.title AS job_title,
            Jobs.location AS job_location,
            EmployerProfiles.company_name AS employer_name,
            EmployerProfiles.user_id AS employer_id
        FROM Applications
        LEFT JOIN Jobs ON Applications.job_id = Jobs.job_id
        LEFT JOIN EmployerProfiles
        ON Jobs.employer_id = EmployerProfiles.user_id
        WHERE Applications.job_seeker_id = ?
        ORDER BY Applications.applied_at DESC
    ''', (job_seeker_id,))
    applications = cursor.fetchall()

    conn.close()

    # Convert to a list of dictionaries for easier handling in the template
    applications_list = []
    for application in applications:
        applications_list.append({
            'application_id': application['application_id'],
            'job_id': application['job_id'],
            'job_title': application['job_title'],
            'job_location': application['job_location'],
            'employer_name': application['employer_name'],
            'employer_id': application['employer_id'],
            'cover_letter': application['cover_letter'],
            'application_status': application['application_status'],
            'cv_file_path': application['cv_file_path'],
            'applied_at': application['applied_at']
        })

    return render_template('jobseeker/track_applications.html',
                           applications=applications_list)


@csrf.exempt
@app.route('/recommended_job/<int:job_id>', methods=['GET'])
def recommended_job_details(job_id):
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Fetch job details
    cursor.execute('''
        SELECT
            Jobs.job_id,
            Jobs.title,
            Jobs.description,
            Jobs.location,
            Jobs.salary_range,
            JobCategories.category_name,
            EmployerProfiles.company_name,
            EmployerProfiles.website,
            EmployerProfiles.linkedin_url
        FROM Jobs
        LEFT JOIN JobCategories ON Jobs.category_id = JobCategories.category_id
        LEFT JOIN EmployerProfiles
        ON Jobs.employer_id = EmployerProfiles.user_id
        WHERE Jobs.job_id = ?
    ''', (job_id,))
    job = cursor.fetchone()

    if not job:
        conn.close()
        flash("Job not found!", "error")
        return redirect(url_for('jobs'))

    conn.close()

    # Render the recommended job details page
    return render_template('recommended_job_details.html', job=dict(job))


@csrf.exempt
@app.route('/toggle_save_job/<int:job_id>', methods=['POST'])
def toggle_save_job(job_id):
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        flash("You need to log in to save jobs.", "error")
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    job_seeker_id = session['user_id']

    try:
        # Check if the job exists in the Jobs table
        cursor.execute("SELECT * FROM Jobs WHERE job_id = ?", (job_id,))
        job_exists = cursor.fetchone()
        if not job_exists:
            flash("The job does not exist.", "error")
            return redirect(url_for('jobs'))

        # Check if the job is already saved
        cursor.execute(
            'SELECT is_saved FROM job_saved WHERE job_seeker_id = ? AND job_id = ?',
            (job_seeker_id, job_id)
        )
        saved_job = cursor.fetchone()

        if saved_job:
            # Toggle is_saved status
            new_status = 0 if saved_job['is_saved'] == 1 else 1
            cursor.execute(
                'UPDATE job_saved SET is_saved = ?, created_at = CURRENT_TIMESTAMP WHERE job_seeker_id = ? AND job_id = ?',
                (new_status, job_seeker_id, job_id)
            )
            flash("Job unsaved successfully." if new_status ==
                  0 else "Job saved successfully.", "success")
        else:
            # Insert a new saved job entry
            cursor.execute(
                '''
                INSERT INTO job_saved (job_seeker_id, job_id, is_saved, created_at)
                VALUES (?, ?, 1, CURRENT_TIMESTAMP)
                ''',
                (job_seeker_id, job_id)
            )
            flash("Job saved successfully.", "success")

        conn.commit()
    except sqlite3.Error as e:
        flash(f"An error occurred: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('jobs'))


@csrf.exempt
@app.route('/view_saved_jobs', methods=['GET'])
def view_saved_jobs():
    """
    Allows job seekers to view their saved jobs.
    """
    # Ensure the user is logged in and is a job seeker
    if 'user_id' not in session or session['user_type'] != 'job_seeker':
        flash("You need to log in to view saved jobs.", "error")
        return redirect(url_for('login'))

    job_seeker_id = session['user_id']

    try:
        # Connect to the database
        conn = get_db()
        cursor = conn.cursor()

        # Fetch saved jobs
        cursor.execute('''
                    SELECT
                        Jobs.job_id,
                        Jobs.title,
                        Jobs.description,
                        Jobs.location,
                        Jobs.salary_range,
                        EmployerProfiles.company_name,
                        EmployerProfiles.logo AS logo
                    FROM job_saved
                    JOIN Jobs ON job_saved.job_id = Jobs.job_id
                    LEFT JOIN EmployerProfiles
                    ON Jobs.employer_id = EmployerProfiles.user_id
                    WHERE job_saved.job_seeker_id = ?
                    AND job_saved.is_saved = 1
                    ORDER BY job_saved.created_at DESC;
        ''', (job_seeker_id,))

        saved_jobs = cursor.fetchall()

    except Exception:
        flash("An error occurred while retrieving saved jobs. Please try again later.", "error")
        return redirect(url_for('job_seeker_index'))

    finally:
        conn.close()
    # Render the saved jobs page
    return render_template('jobseeker/saved_jobs.html', saved_jobs=saved_jobs)


@app.route('/employer/<int:employer_id>')
def view_employer(employer_id):
    conn = get_db()
    cursor = conn.cursor()

    # Fetch employer details
    cursor.execute('''
        SELECT
            company_name, logo, location, website,
            description, company_size, established_year,
            contact_person, contact_email, contact_phone
        FROM EmployerProfiles
        WHERE user_id = ?
    ''', (employer_id,))
    employer = cursor.fetchone()

    if not employer:
        conn.close()
        flash("Employer not found!", "error")
        return redirect(url_for('jobs'))

    # Fetch recent job postings by this employer
    cursor.execute('''
        SELECT job_id, title, location, job_type, posted_at
        FROM Jobs
        WHERE employer_id = ? AND is_active = 1
        ORDER BY posted_at DESC
        LIMIT 5
    ''', (employer_id,))
    recent_jobs = cursor.fetchall()

    conn.close()

    return render_template(
        'jobseeker/view_employer.html',
        employer=dict(employer),
        recent_jobs=[dict(job) for job in recent_jobs]
    )

# Route for logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing_page'))


@app.route('/about_us', methods=['GET'])
def about_us():
    # Render the About Us page
    return render_template('jobseeker/about_us.html')


if __name__ == '__main__':
    app.run(debug=True)
