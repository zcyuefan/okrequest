from flask import Flask, jsonify, request
from flask_jwt import JWT, jwt_required, current_identity, JWTError
from flask_restful import Api, Resource, abort, reqparse
from werkzeug.security import safe_str_cmp
from flasgger import Swagger


class User(object):
    def __init__(self, user_id, username, password):
        self.id = user_id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id


users = [
    User(1, 'guest', 'secret'),
]

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}


def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user


def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)


app = Flask(__name__)
app.debug = True
api = Api(app)
app.config["SECRET_KEY"] = "super-secret"
app.config["SWAGGER"] = {
    "title": "Swagger JWT Authentiation App",
    "uiversion": 3,
}
app.config['JWT_AUTH_URL_RULE'] = '/api/auth'
app.config['JWT_AUTH_HEADER_NAME'] = 'JWTAuthorization'
app.config['JWT_AUTH_HEADER_PREFIX'] = 'Bearer'

swag = Swagger(app)


def jwt_request_handler():
    auth_header_name = app.config['JWT_AUTH_HEADER_NAME']
    auth_header_value = request.headers.get(auth_header_name, None)
    auth_header_prefix = app.config['JWT_AUTH_HEADER_PREFIX']

    if not auth_header_value:
        return

    parts = auth_header_value.split()

    if parts[0].lower() != auth_header_prefix.lower():
        raise JWTError('Invalid JWT header', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise JWTError('Invalid JWT header', 'Token missing')
    elif len(parts) > 2:
        raise JWTError('Invalid JWT header', 'Token contains spaces')

    return parts[1]


jwt = JWT(app, authenticate, identity)
jwt.request_handler(jwt_request_handler)


@app.route("/login", methods=["POST"])
def login():
    """
    User authenticate method.
    ---
    description: Authenticate user with supplied credentials.
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
    responses:
      200:
        description: User successfully logged in.
      400:
        description: User login failed.
    """
    try:
        username = request.form.get("username")
        password = request.form.get("password")

        user = authenticate(username, password)
        if not user:
            raise Exception("User not found!")

        resp = jsonify({"message": "User authenticated"})
        resp.status_code = 200

        access_token = jwt.jwt_encode_callback(user)

        # add token to response headers - so SwaggerUI can use it
        resp.headers.extend({'jwt-token': access_token})

    except Exception as e:
        resp = jsonify({"message": "Bad username and/or password"})
        resp.status_code = 401

    return resp


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    """
    Protected content method.
    ---
    description: Protected content method. Can not be seen without valid token.
    responses:
      200:
        description: User successfully accessed the content.
    """
    resp = jsonify({"protected": "{} - you saw me!".format(current_identity)})
    resp.status_code = 200

    return resp


@app.route('/colors/<palette>/')
def colors(palette):
    """Example endpoint returning a list of colors by palette
    This is using docstrings for specifications.
    ---
    tags:
      - demo
    parameters:
      - name: palette
        in: path
        type: string
        enum: ['all', 'rgb', 'cmyk']
        required: true
        default: all
    definitions:
      Palette:
        type: object
        properties:
          palette_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by palette)
        schema:
          $ref: '#/definitions/Palette'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {
        'cmyk': ['cian', 'magenta', 'yellow', 'black'],
        'rgb': ['red', 'green', 'blue']
    }
    if palette == 'all':
        result = all_colors
    else:
        result = {palette: all_colors.get(palette)}

    return jsonify(result)


TODOS = {
    'todo1': {'task': 'build an API'},
    'todo2': {'task': '?????'},
    'todo3': {'task': 'profit!'},
    '42': {'task': 'Use Flasgger'}
}


def abort_if_todo_doesnt_exist(todo_id):
    if todo_id not in TODOS:
        abort(404, message="Todo {} doesn't exist".format(todo_id))


parser = reqparse.RequestParser()
parser.add_argument('task')


# Todo
# shows a single todo item and lets you delete a todo item
class Todo(Resource):
    def get(self, todo_id):
        """
        This is an example
        ---
        tags:
          - restful
        parameters:
          - in: path
            name: todo_id
            required: true
            description: The ID of the task, try 42!
            type: string
        responses:
          200:
            description: The task data
            schema:
              id: Task
              properties:
                task:
                  type: string
                  default: My Task
        """
        abort_if_todo_doesnt_exist(todo_id)
        return TODOS[todo_id]

    def delete(self, todo_id):
        """
        This is an example
        ---
        tags:
          - restful
        parameters:
          - in: path
            name: todo_id
            required: true
            description: The ID of the task, try 42!
            type: string
        responses:
          204:
            description: Task deleted
        """
        abort_if_todo_doesnt_exist(todo_id)
        del TODOS[todo_id]
        return '', 204

    def put(self, todo_id):
        """
        This is an example
        ---
        tags:
          - restful
        parameters:
          - in: body
            name: body
            schema:
              $ref: '#/definitions/Task'
          - in: path
            name: todo_id
            required: true
            description: The ID of the task, try 42!
            type: string
        responses:
          201:
            description: The task has been updated
            schema:
              $ref: '#/definitions/Task'
        """
        args = parser.parse_args()
        task = {'task': args['task']}
        TODOS[todo_id] = task
        return task, 201


# TodoList
# shows a list of all todos, and lets you POST to add new tasks
class TodoList(Resource):
    def get(self):
        """
        This is an example
        ---
        tags:
          - restful
        parameters:
          - in: query
            name: page
            required: false
            description: Page number！
            type: number
          - in: query
            name: limit
            required: false
            description: Page limit!
            type: number
        responses:
          200:
            description: The task data
            schema:
              id: Tasks
              properties:
                task_id:
                  type: object
                  schema:
                    $ref: '#/definitions/Task'
        """
        return TODOS

    def post(self):
        """
        This is an example
        ---
        tags:
          - restful
        parameters:
          - in: body
            name: body
            schema:
              $ref: '#/definitions/Task'
        responses:
          201:
            description: The task has been created
            schema:
              $ref: '#/definitions/Task'
        """
        args = parser.parse_args()
        todo_id = int(max(TODOS.keys()).lstrip('todo')) + 1
        todo_id = 'todo%i' % todo_id
        TODOS[todo_id] = {'task': args['task']}
        return TODOS[todo_id], 201


api.add_resource(TodoList, '/todos')
api.add_resource(Todo, '/todos/<todo_id>')


if __name__ == '__main__':
    app.run()
