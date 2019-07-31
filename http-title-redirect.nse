local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Shows the title of a specified or default page ("/") of a web server.
The script will follow up to 10 HTTP/S redirects by default.
]]

---
--@args http-title-redirect.url The url to fetch. Default: /
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | title: Go ahead and ScanMe!
-- |_redirectCount: 3
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>

author = "Scott Goetzinger"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
	local response, path, title, redirectObject
	local output = stdnse.output_table()
	local redirectCount = 0
	local maxRedirectNum = 10 

	path = stdnse.get_script_args(SCRIPT_NAME..".url")

	response = http.get(host, port, path or "/" )

	--check if initial request is redirected, if so follow a maximum of 10 redirections
	if (tostring(response.status):match("30%d") and response.header.location) then
		redirectObject = http.parse_redirect(host, port, path or "/", response)
		redirectCount = redirectCount + 1

		while (tostring(response.status):match("30%d") and response.header.location) and (redirectCount < maxRedirectNum) do
			redirectCount = redirectCount + 1
			response = http.get(redirectObject.host, redirectObject.port, redirectObject.path)
			redirectObject = http.parse_redirect(redirectObject.host, redirectObject.port, redirectObject.path, response)
		end
	end

	--check if still being redirected and max redirect number has been reached
	if (tostring(response.status):match("30%d") and response.header.location and (redirectCount == maxRedirectNum)) then
		output.error = ("Followed max allowed redirects, last location provided: %s"):format(redirectObject.path)
		output.redirectCount = redirectCount
		return output
	end
	 
	--check if there is a body
	if not response.body then
		output.error = "No data in body"
		output.redirectCount = redirectCount
		return output
	end

	--check for title in body, and remove new lines and tabs
	title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

	if title then
		output.title = string.gsub(title, "[\n\r\t]", "")
	else
		output.error = "No title in body"
		output.redirectCount = redirectCount
		return output
	end

	output.redirectCount = redirectCount
	return output
end
