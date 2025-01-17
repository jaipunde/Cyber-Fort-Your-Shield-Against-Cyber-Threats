from flask import Blueprint, render_template, request, jsonify, send_file
import subprocess
import re
import requests
import hashlib
import pymysql

views = Blueprint("views", __name__)

#MySQL Configuration
# views.config['MYSQL_HOST'] = 'localhost'
# views.config['MYSQL_USER'] = 'root'
# views.config['MYSQL_PASSWORD'] = ''
# views.config['MYSQL_DB'] = 'college'

@views.route('/')
def index():
    return render_template("index.html")

@views.route('/about')
def about():
    return render_template("about.html")

@views.route('/service')
def service():
    return render_template("service.html")

@views.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        # Insert into MySQL database
        conn = pymysql.connect(host='localhost', user='root', password='ubuntu', database='college')
        cursor = conn.cursor()
        sql_query = "INSERT INTO sentinel (name, email, subject, message) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql_query, (name, email, subject, message))
        conn.commit()
        conn.close()
        
        return '<script>alert("Thank you! Your Message has been sent successfuly"); window.location.href="/contact";</script>'
    
    else:
        return render_template("contact.html")

@views.route('/policy')
def policy():
    return render_template("policy.html")

@views.route('/terms')
def terms():
    return render_template("terms.html")

@views.route('/service/port-scanner')
def portScanner():
    return render_template("port-scanner.html")

@views.route('/service/malware-scanner')
def malwareScanner():
    return render_template("malware-scanner.html")

@views.route('/service/volatile-vm')
def volatileVM():
    return render_template("volatile-vm.html")

@views.route('/service/volatile-vm/download')
def download_file():
    file_path = '/home/ubuntu/Server/VolatileVM/VolatileVM.rar'
    return send_file(file_path, as_attachment=True)

@views.route('/service/vulnerability-scanner')
def vulnerabilityScanner():
    return render_template("vulnerability-scanner.html")

@views.route('/results/port-scan', methods=['POST'])
def scanPorts():
    target = request.form.get('target')
    port_range = request.form.get('portRange')

    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    url_regex = r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$'


    if not target or not port_range or (not re.match(ip_regex, target) and not re.match(url_regex, target)):
        return "Error: Invalid target or port range", 400


    # Determine nmap arguments based on port range
    if port_range == 'all':
        ports = '-p-'
    else:  # Assume 'common'
        ports = '-p20,21,22,23,25,53,80,110,443'

    # Run nmap and capture its output
    result = subprocess.run(f'nmap -sC -sV {ports} -oX /home/ubuntu/Results/result.xml --stylesheet /home/ubuntu/Results/nmap-bootstrap.xsl {target}', shell=True, text=True, capture_output=True)
    subprocess.run(['xsltproc -o /home/ubuntu/Project/templates/results/result.html /home/ubuntu/Results/nmap-bootstrap.xsl /home/ubuntu/Results/result.xml'], shell=True)

    return render_template('/results/result.html')

@views.route('/api/scan', methods=['POST'])
def scan_file():
    # Get the uploaded file
    uploaded_file = request.files['file']
    
    if not uploaded_file:
        return jsonify({'error': 'No file uploaded'}), 400
    
    # VirusTotal API key
    api_key = '317d90e8d30b27cf62ca84a905f03f25f4848509df132b8dfaa15d9cbb7135b4'
    scan_url = 'https://www.virustotal.com/api/v3/'
    
    # Prepare headers with the API key
    headers = {
        'x-apikey': api_key
    }
    
    # Prepare the file data
    files = {
        'file': (uploaded_file.filename, uploaded_file.stream)
    }
    
    try:
        response = requests.post(scan_url + "files", files=files, headers=headers)
        
        if response.status_code == 200:
            sha256_hash = hashlib.sha256()
            uploaded_file.stream.seek(0)
            for chunk in iter(lambda: uploaded_file.stream.read(4096), b""):
                sha256_hash.update(chunk)
            sha256 = sha256_hash.hexdigest()

            return jsonify({'url' : f"https://www.virustotal.com/ui/file_behaviours/{sha256}_Zenbox/html"})
        
        else:
            return jsonify({'error': 'Failed to upload file to VirusTotal'}), response.status_code
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500