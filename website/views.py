from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from . import db
import json


views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        return jsonify({})
    return render_template("convert.html", user=current_user)


