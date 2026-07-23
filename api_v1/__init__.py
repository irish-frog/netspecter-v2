from .blueprint import api_v1


def register_api(app):
    app.register_blueprint(api_v1)
