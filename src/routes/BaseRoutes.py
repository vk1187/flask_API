from flask import Blueprint


# hello = Blueprint('hello', __name__, url_prefix='/hello')
def getNewRoute(name):
    '''	 /apis/ is the subfolder set on server nginx. '''
    return Blueprint(name, __name__, url_prefix='/prodcoachapi/v1/'+name)

'''	 Function for checking base working. '''
def check():
    return "Welcome to the app base!"

def checkApis():
    return "Welcome to the apis base!"

'''	 Adding base route so that can check server running. '''
routes = Blueprint('base', __name__, url_prefix='/')
routes.add_url_rule('/', view_func=check)

'''	 As subdomain is set on /prodcoachapi/. '''
routes.add_url_rule('prodcoachapi/', view_func=checkApis)

'''  As subdomain is set on /graphql/. '''
from ..libs.zenarateGraphQL.base_schema import schema

from flask_graphql import GraphQLView

routes.add_url_rule(
    "/graphql/v1", view_func=GraphQLView.as_view("graphql", schema=schema, graphiql=True)
)

