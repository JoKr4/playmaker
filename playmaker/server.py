import os
import tornado

from tornado import web
from tornado.concurrent import run_on_executor
from tornado.web import MissingArgumentError
from concurrent.futures import ThreadPoolExecutor


app_dir = os.path.dirname(os.path.realpath(__file__))
static_dir = os.path.join(app_dir, 'static')
fdroid_instance = {}


def createServer(service):

    class HomeHandler(web.RequestHandler):
        def get(self):
            with open(app_dir + '/index.html', 'r') as f:
                self.write(f.read())

    class ApiHandler(web.RequestHandler):
        executor = ThreadPoolExecutor()

        @run_on_executor
        def get_apps(self):
            return service.get_apps()

        @run_on_executor
        def get_last_fdroid_update(self):
            return service.get_last_fdroid_update()

        @run_on_executor
        def search(self):
            try:
                keyword = self.get_argument('search')
            except MissingArgumentError:
                return None
            return service.search(keyword)

        @run_on_executor
        def login(self):
            data = tornado.escape.json_decode(self.request.body)
            service.set_encoded_credentials(data.get('email'), data.get('password'))
            return service.login()

        @run_on_executor
        def download(self):
            data = tornado.escape.json_decode(self.request.body)
            if data.get('download') is None:
                return None
            return service.download_new_app(data['download'])

        @run_on_executor
        def check(self):
            return service.check_local_apks()

        @run_on_executor
        def update_state(self):
            service.update_state()

        @run_on_executor
        def remove_app(self, app):
            return service.remove_local_app(app)

        @run_on_executor
        def update_fdroid(self):
            return service.fdroid_update()

        @tornado.gen.coroutine
        def get(self, path):
            if path == 'apps':
                apps = yield self.get_apps()
                self.write(apps)
            elif path == 'search':
                apps = yield self.search()
                if apps is not None:
                    self.write(apps)
                else:
                    self.clear()
                    self.set_status(400, 'You should supply a valid search query')
            elif path == 'lastfdroidupdate':
                result = yield self.get_last_fdroid_update()
                self.write(result)
            elif path == 'lastplaymakerupdate':
                result = yield self.get_last_playmaker_update()
                self.write(result)
            else:
                self.set_status(404)
            self.finish()

        @tornado.gen.coroutine
        def post(self, path):
            if path == 'download':
                result = yield self.download()
                if result is None:
                    self.clear()
                    self.set_status(400)
                else:
                    self.write(result)
            elif path == 'check':
                result = yield self.check()
                self.write(result)
            elif path == 'login':
                result = yield self.login()
                self.write(result)
                if result['status'] == 'SUCCESS' and result['message'] == 'OK':
                    self.update_state()
            elif path == 'fdroid':
                global fdroid_instance
                if fdroid_instance != {}:
                    self.write({'status': 'PENDING'})
                else:
                    fdroid_instance = self
                    result = yield self.update_fdroid()
                    self.write(result)
                    fdroid_instance = {}
            else:
                self.set_status(404)
            self.finish()

        @tornado.gen.coroutine
        def delete(self, path):
            if path == 'delete':
                data = tornado.escape.json_decode(self.request.body)
                if data.get('delete') is None:
                    self.clear()
                    self.set_status(400)
                else:
                    result = yield self.remove_app(data['delete'])
                    self.write(result)
            else:
                self.set_status(404)
            self.finish()

    if service.fdroid:
        app = web.Application([
            (r'/', HomeHandler),
            (r'/api/(.*?)/?', ApiHandler),
            (r'/fdroid/(.*)', web.StaticFileHandler, {'path': service.fdroid_repo}),
            (r'/static/(.*)', web.StaticFileHandler, {'path': static_dir}),
            (r'/views/(.*)', web.StaticFileHandler, {'path': app_dir + '/views'}),
        ], debug=False)
    else:
        app = web.Application([
            (r'/', HomeHandler),
            (r'/api/(.*?)/?', ApiHandler),
            (r'/static/(.*)', web.StaticFileHandler, {'path': static_dir}),
            (r'/views/(.*)', web.StaticFileHandler, {'path': app_dir + '/views'}),
        ], debug=False)

    # overwrite settings
    app.settings['static_path'] = ''
    return app
