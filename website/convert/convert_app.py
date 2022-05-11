from flask import Flask, Blueprint, render_template, request, redirect, send_file, flash, jsonify, url_for
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from subprocess import check_output
from io import BytesIO
import base64
from .sniffer_converter import Convert2Pcap
from ..models import Conversion
from .. import db
import json



conv = Blueprint('conv', __name__, template_folder='templates',
    static_folder='static'
)



@conv.route('/upload/', methods=['POST', 'GET'])
@login_required
def upload():
    files_table = Conversion.query.order_by(Conversion.date_created).all()
    if request.method == 'POST':
        task_content = request.files['InputFile']
        try:
            new_task = Conversion(content=task_content.filename, data=task_content.read(), user_id=current_user.id)
            print(type(new_task))
            db.session.add(new_task)
            db.session.commit()
            flash('File added!', category='success')
            return redirect(url_for('.upload'))
        except:
            return jsonify({'Issue adding your sniffer to table'})
    else:
        return render_template('convert.html', tasks=files_table, user=current_user)

@conv.route('/delete/<int:id>')
@login_required
def delete(id):
    task = Conversion.query.get_or_404(id)
    if current_user.id == task.user_id:
        try:
            db.session.delete(task)
            db.session.commit()
            flash('File deleted!', category='success')
            return redirect(url_for('.upload'))
        except:
            return jsonify({"Could not delete task"})

@conv.route('/rename/', methods=['POST'])
@login_required
def rename():
    task = json.loads(request.data)
    taskId = task['id']
    newName = task['newname']
    task = Conversion.query.get_or_404(taskId)
    if current_user.id == task.user_id:
        task.content = newName
        db.session.commit()
        flash('File renamed!', category='success')
    return jsonify({'Could not rename file'})

@conv.route('/downloadpre/<int:id>', methods=['GET'])
@login_required
def downloadpre(id):
    task = Conversion.query.get_or_404(id)
    if current_user.id == task.user_id:
        try:
            return send_file(BytesIO(task.data), attachment_filename=task.content, as_attachment=True)
        except:
            return jsonify({"Could not return task"})

@conv.route('/downloadpost/<int:id>', methods=['GET'])
@login_required
def downloadpost(id):
    task = Conversion.query.get(id)
    if current_user.id == task.user_id:
        try:
            return send_file(BytesIO(task.data_converted), attachment_filename=f'{task.content}.pcap', as_attachment=True)
        except:
            return jsonify({"Could not return task"})

@conv.route('/convert/<int:id>', methods=['GET'])
@login_required
def convert(id):
    task = Conversion.query.get(id)
    task_file = Conversion.query.get(id).data.decode('utf-8', errors='ignore')
    output_file = Convert2Pcap.run_conversion(id, current_user.id, task.user_id, task.content, task_file)
    if not output_file:
        flash('Unable to convert your file.', category='error')
        return redirect(url_for('.upload'))
    else:
        with open(output_file, 'rb') as pcapfr:
            pcapfrb = pcapfr.read()
            task = Conversion.query.get_or_404(id)
            task.data_converted = pcapfrb
            try:
                db.session.commit()
                os.remove(output_file)
                flash('File converted!', category='success')
                return redirect(url_for('.upload'))
            except:
                flash('Unable to convert your file.', category='error')
                return redirect(url_for('.upload'))

@conv.route('/converted/<int:id>', methods=['GET'])
def converted(id):
    task = Conversion.query.get_or_404(id)
    if task.data_converted:
        return task.data_converted
    else:
        return jsonify({'File has not been converted'})

