from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ipuser:qwe1236@localhost/iptable'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class IPTable(db.Model):
    __tablename__ = 'iptable'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    gateway = db.Column(db.String(255))
    ip = db.Column(db.String(255))
    host = db.Column(db.String(255))
    part = db.Column(db.String(255))
    name = db.Column(db.String(255))
    place = db.Column(db.String(255))
    phone = db.Column(db.String(255))
    etcs = db.Column(db.String(244))
    date = db.Column(db.String(255))
    class_ = db.Column("class", db.String(255))
    num = db.Column(db.String(255))

@app.route('/api/iptable', methods=['GET'])
def get_iptable():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 1000, type=int)
    iptable_query = IPTable.query.paginate(page, per_page, error_out=False)
    items = [item.as_dict() for item in iptable_query.items]
    return jsonify({
        'items'
    })
@app.route('/')
def index():
    ips = IPTable.query.all()
    return render_template('index.html', ips=ips)

@app.route('/add', methods=['POST'])
def add():
    gateway = request.form['gateway']
    ip = request.form['ip']
    host = request.form['host']
    part = request.form['part']
    name = request.form['name']
    place = request.form['place']
    phone = request.form['phone']
    etcs = request.form['etcs']
    date = request.form['date']
    class_ = request.form['class']
    num = request.form['num']

    new_ip = IPTable(
        gateway=gateway, ip=ip, host=host, part=part, name=name,
        place=place, phone=phone, etcs=etcs, date=date, class_=class_, num=num
    )
    db.session.add(new_ip)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
