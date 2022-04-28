from flask import Flask, Blueprint, render_template, request, redirect, send_from_directory, send_file, flash, jsonify
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy
import os
from subprocess import check_output
from io import BytesIO
import base64
from .sniffer_converter import convert2pcap
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
            db.session.add(new_task)
            db.session.commit()
            flash('File added!', category='success')
            return redirect('/upload')
        except:
            return 'Issue adding your sniffer to table'
    else:
        return render_template('convert.html', tasks=files_table, user=current_user)

@conv.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Conversion.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('File deleted!', category='error')
        return redirect('/upload')
    except:
        return "Could not delete task"

@conv.route('/rename/', methods=['POST'])
@login_required
def rename():
    task = json.loads(request.data)
    taskId = task['id']
    newName = task['newname']
    task = Conversion.query.get_or_404(taskId)
    if task:
        if task.user_id == current_user.id:
            task.content = newName
            db.session.commit()
            flash('File renamed!', category='success')
    return jsonify({})



@conv.route('/convert/<int:id>', methods=['GET'])
def convert(id):
    task_to_convert = Conversion.query.get(id).data.decode('utf-8')
    pcapc = convert2pcap(id)
    output_file, input_file = pcapc.cv2pc(task_to_convert)
    if output_file:
        with open(output_file, 'rb') as pcapfr:
            pcapfrb = pcapfr.read()
            task = Conversion.query.get_or_404(id)
            task.data_converted = pcapfrb
            try:
                db.session.commit()
                os.remove(input_file)
                os.remove(output_file)
                return redirect('/')
            except:
                return 'Issue adding your task'

@conv.route('/converted/<int:id>', methods=['GET'])
def converted(id):
    task = Conversion.query.get_or_404(id)
    if task.data_converted:
        return task.data_converted
    else:
        return f'File has not been converted'

@conv.route('/downloadpre/<int:id>', methods=['GET'])
def downloadpre(id):
    task_to_convert = Conversion.query.get(id)
    try:
        return send_file(task_to_convert.data, attachment_filename='InputFile.txt', as_attachment=True)
    except:
        return "Could not return task"

@conv.route('/downloadpost/<int:id>', methods=['GET'])
def downloadpost(id):
    task = Conversion.query.get(id)
    try:
        return send_file(BytesIO(task.data_converted), attachment_filename='OutputFile.pcap', as_attachment=True)
    except:
        return "Could not return task"