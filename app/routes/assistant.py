from flask import Blueprint, render_template, request, jsonify, session
from flask_login import login_required

from app.logic.ai_assistant import AIInvestigationAssistant

assistant_bp = Blueprint('assistant', __name__, url_prefix='/assistant')

# One shared instance (stateless — all state is in the session or passed in)
_assistant = AIInvestigationAssistant()


@assistant_bp.route('/')
@login_required
def chat_page():
    history = session.get('assistant_history', [])
    return render_template('assistant/chat.html', history=history)


@assistant_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json(force=True)
    user_message = (data.get('message') or '').strip()
    if not user_message:
        return jsonify({'error': 'Empty message'}), 400

    # Retrieve per-session conversation history
    history = session.get('assistant_history', [])

    response = _assistant.answer(user_message, conversation_history=history)

    # Update history (keep last 10 turns = 5 exchanges)
    history.append({'role': 'user',      'content': user_message})
    history.append({'role': 'assistant', 'content': response.reply})
    session['assistant_history'] = history[-10:]

    return jsonify({
        'reply':             response.reply,
        'intent':            response.intent,
        'context_used':      response.context_used,
        'validation_passed': response.validation_passed,
        'warning':           response.warning,
    })


@assistant_bp.route('/clear', methods=['POST'])
@login_required
def clear():
    session.pop('assistant_history', None)
    return jsonify({'status': 'cleared'})