# app.py - NetMonitor Flask Application 
# This is the entry point of the web application

from flask import Flask, render_template

# Create the Flask app instance
# __name__ tellse Flask where to find templates and static files
app = Flask(__name__)

#This is a "route" - it tells Falsk what to do when someone visits a URL

@app.route("/")
def dashboard():
	"""Main dashboard page - shows all network devices and their status."""
	devices = [
	{ 
	"id": 1,
	"name": "Cisco Sandbox Router",
	"ip_address": "sandbox-iosxe-latest-1.cisco.com",
	"device_type": "cisco_ios",
	"status": "unknown",
	"last_checked": "Not Yet checked"
	},

	{"id": 2,
	"name": "Google DNS",
	"ip_address": "8.8.8.8",
 	"device_type": "other",
	"status": "unknown",
	"last_checked": "Not yet checked"
	},

	{"id": 3,
	"name": "Cloudflare DNS",
	"ip_address": "1.1.1.1",
	"device_type": "other",
	"status": "unknown",
	"last_checked": "Not yet checked"
	}
		]
	return render_template("dashboard.html", devices=devices)

if __name__ == "__main__":
	app.run(debug=True)
