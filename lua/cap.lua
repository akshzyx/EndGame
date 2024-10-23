aes = require "resty.aes"
hmac = require "resty.hmac"
str = require "resty.string"
cook = require "resty.cookie"
random = require "resty.random"
sha256 = require "resty.sha256"

-- encryption key and salt must be shared across fronts. salt must be 8 chars. Key is not used anymore just kept for reference.
-- local key = "encryption_key"
local salt = "salt1234"
-- for how long the captcha is valid. 120 sec is for testing, 3600 1 hour should be production.
local session_timeout = sessionconfigvalue

-- needed for reading the master key
function fromhex(hex_str)
    local bin_str = ""

    for i = 1, #hex_str, 2 do
        local hex_char = string.sub(hex_str, i, i+1)
        bin_str = bin_str .. string.char(tonumber(hex_char, 16))
    end

    return bin_str
end

-- generated in setup.sh based on the encryption key using PBKDF2, which hardens it
-- against bruteforce attacks, making the implementation a little more foolproof, here's the command used:
-- OPENSSL 3:
-- openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:$KEY -kdfopt salt:$SALT -kdfopt iter:2000000 PBKDF2 | sed s/://g
-- OPENSSL 1.1.1n:
-- openssl enc -aes-256-cbc -pbkdf2 -pass pass:$KEY -S $SALT_HEX -iter 2000000 -md sha256 -P | grep "key" | sed s/key=//g
local master_key = fromhex("masterkeymasterkeymasterkey")

b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function base64_encode(data)
    return ((data:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function base64_decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

function hmac_digest(key, data)
    local hmac_sha256_lib = hmac:new(key, hmac.ALGOS.SHA256)
    hmac_sha256_lib:update(data)
    return hmac_sha256_lib:final()
end

function sha256_digest(data)
    local sha256_lib = sha256:new()
    sha256_lib:update(data)
    return sha256_lib:final()
end

-- This function encrypts the cookie and outputs it ready for use in the following format : base64(cookie_token + cookie_ciphertext + cookie_tag)
-- cookie_token is 32 bytes
-- cookie_ciphertext is variable
-- cookie_tag is 16 bytes
function encrypt(cookie_plaintext)
    local cookie_token = sha256_digest(random.token(32))
    local derived_key = hmac_digest(master_key, cookie_token)
    local aes_ctx = aes:new(derived_key, salt, aes.cipher(256, "gcm"), aes.hash.sha256, 1, 12)
    local encrypted = aes_ctx:encrypt(cookie_plaintext)
    return base64_encode(cookie_token .. encrypted[1] .. encrypted[2])
end

-- This function decrypts the cookie as it is received, no need to decode base64 or parse anything.
-- returns nil if any step of the decryption fails
function decrypt(cookie_ciphertext)
    local decoded_cookie = base64_decode(cookie_ciphertext)
    -- cookie should be at least 49 bytes long (32 for the token + 16 for the tag + at least 1 for the content)
    if (#decoded_cookie <= 48) then
        return nil, "Decoded cookie too short (<= 48 bytes)"
    end
    -- parsing the cookie
    local cookie_token = string.sub(decoded_cookie, 1, 32)
    local cookie_ciphertext = string.sub(decoded_cookie, 33, (#decoded_cookie - 16))
    local cookie_tag = string.sub(decoded_cookie, (#decoded_cookie - 15), #decoded_cookie)
    -- deriving the key and setting up AES context
    local derived_key = hmac_digest(master_key, cookie_token)
    local aes_ctx = aes:new(derived_key, salt, aes.cipher(256, "gcm"), aes.hash.sha256, 1, 12)
    return aes_ctx:decrypt(cookie_ciphertext, cookie_tag)
end

function killconnection(pa)
    if pa ~= "no_proxy" then
        local ok, err = ngx.timer.at(0, kill_circuit, ngx.var.remote_addr, ngx.var.proxy_protocol_addr)
        if not ok then
            ngx.log(ngx.ERR, "failed to create timer: ", err)
            return
        end
    end
end

function blockcookies(field)
    ngx.shared.blocked_cookies:set(field, 1, 3600)
end

function generalerror()
    ngx.header.content_type = "text/plain"
    ngx.say("403 DDOS filter killed your path. (You probably sent too many requests at once). Not calling you a bot, bot, but grab a new identity and try again.")
    ngx.flush()
    ngx.exit(403)
end

function sessionexpired()
    ngx.header.content_type = "text/html"
    ngx.say('<h1>EndGame Session has expired</h1> <h3>and the post request was not processed.</h3> <p><a target="_blank" href="/">After you pass another captcha</a> (clicking opens new tab), you can reload this page (press F5) and submit the request again to prevent data loss. <b>If you leave this page without submitting again, what you just submitted will be lost.</b></p>')
    ngx.flush()
    ngx.exit(401)
end

function killblockdrop(pa, field)
    if pa ~= nil then
        killconnection(pa)
    end
    if field ~= nil then
        blockcookies(field)
    end
    ngx.exit(444)
end

local cookie, err = cook:new()
if not cookie then
    ngx.log(ngx.ERR, err)
    return
end

-- check proxy_protocol_addr if present kill circuit if needed
pa = "no_proxy"
if ngx.var.proxy_protocol_addr ~= nil then
    pa = ngx.var.proxy_protocol_addr
end

-- if "Host" header is invalid / missing kill circuit and return nothing
if in_array(allowed_hosts, ngx.var.http_host) == nil then
    ngx.log(ngx.ERR, "Wrong host (" .. ngx.var.http_host .. ") " .. ngx.var.remote_addr .. "|" .. pa)
    killblockdrop(pa, nil)
end

-- only GET and POST requests are allowed the others are not used.
if ngx.var.request_method ~= "POST" and ngx.var.request_method ~= "GET" then
    ngx.log(ngx.ERR, "Wrong request (" .. ngx.var.request_method .. ") " .. ngx.var.remote_addr .. "|" .. pa)
    killblockdrop(pa, nil)
end

-- requests without user-agent are usually invalid
if ngx.var.http_user_agent == nil then
    ngx.log(ngx.ERR, "Missing user agent " .. ngx.var.remote_addr .. "|" .. pa)
    killblockdrop(pa, nil)
end

-- POST without referer is invalid. some poorly configured clients may complain about this
if ngx.var.request_method == "POST" and ngx.var.http_referer == nil then
    ngx.log(ngx.ERR, "Post without referer " .. ngx.var.remote_addr .. "|" .. pa)
    killblockdrop(pa, nil)
end

-- get cookie
local field, err = cookie:get("dcap")
-- check if cookie is valid.
if not err and field ~= nil then
    if type(field) ~= "string" then
        ngx.log(ngx.ERR, "Invalid dcap value! Not string!" .. ngx.var.remote_addr .. "|" .. pa)
        killblockdrop(pa, nil)
    end
    if not string.match(field, "^([A-Za-z0-9+/=]+)$") then
        ngx.log(ngx.ERR, "Invalid dcap value! Incorrect format! (" .. field .. ")" .. ngx.var.remote_addr .. "|" .. pa)
        killblockdrop(pa, nil)
    end
end

-- check blacklisted by rate limiter. if it is show the client a message and exit. can get creative with this.
local blocked_cookies = ngx.shared.blocked_cookies
local bct, btcflags = blocked_cookies:get(field)
if bct then
    generalerror()
end

-- Check dcap cookie get variable to bypass endgame! Allows some cross site attacks! Enable if need this feature.

-- local args = ngx.req.get_uri_args(2)
-- for key, val in pairs(args) do
--     if key == "dcapset" then
--         plaintext = aes_256_gcm_sha256x1:decrypt(fromhex(val))
--         if not plaintext then
--             killconnection(pa)
--             blockcookies(field)
--             ngx.exit(444)
--         end
--         cookdata = split(plaintext, "|")
--         if (cookdata[1] == "captcha_solved") then
--             if (tonumber(cookdata[2]) + session_timeout) > ngx.now() then
--                 local ok, err =
--                 cookie:set(
--                 {
--                     key = "dcap",
--                     value = val,
--                     path = "/",
--                     domain = ngx.var.host,
--                     httponly = true,
--                     max_age = math.floor((tonumber(cookdata[2]) + session_timeout)-ngx.now()+0.5),
--                     samesite = "Lax"
--                })
--                if not ok then
--                    ngx.log(ngx.ERR, err)
--                    return
--                end
--                field = val
--                err = nil
--             end
--         end
--     end
-- end

caperror = nil

-- check cookie support similar to testcookie
if ngx.var.request_method == "GET" then
    if err or field == nil then
        if ngx.var.http_sec_fetch_site == "cross-site" then
            ngx.header.content_type = "text/html"
            ngx.say("<head><link rel=\"icon\" href=\"data:;base64,iVBORw0KGgo=\"></head><p><a href=\"/\"><span class=\"btn\">Click here to enter...</span></a></p>")
            ngx.flush()
            ngx.exit(200)
        end
        local ni = random.number(5,20)
        local tstamp = ngx.now() + ni
        local plaintext = random.token(random.number(5, 20)) .. "|queue|" .. tstamp .. "|" .. pa .. "|"
        local ciphertext = encrypt(plaintext)
        local ok, err =
            cookie:set(
            {
                key = "dcap",
                value = ciphertext,
                path = "/",
                domain = ngx.var.host,
                httponly = true,
                max_age = 30,
                samesite = "Lax"
            }
        )
        if not ok then
            ngx.log(ngx.ERR, err)
            return
        end
        ngx.header["Refresh"] = ni
        ngx.header.content_type = "text/html"
        local file = io.open("/etc/nginx/resty/queue.html")
        if not file then
            ngx.exit(500)
        end
        local queue, err = file:read("*a")
        file:close()
        ngx.say(queue)
        ngx.flush()
        ngx.exit(200)
    else
        plaintext = decrypt(field)
        if not plaintext then
            killblockdrop(pa, field)
        end
        cookdata = split(plaintext, "|")
        if (cookdata[2] == "queue") then
            if tonumber(cookdata[3]) > ngx.now() or ngx.now() > tonumber(cookdata[3]) + 60 then
                killblockdrop(pa, field)
            end

            --in high levels of attack this system may make reachability of your service worse. But it protects against certain kinds of dcap caching attacks.
            if "no_proxy" ~= cookdata[4] then
                if pa ~= cookdata[4] then
                    ngx.log(ngx.ERR, "QUEUE: Incorrect circuit id (" .. cookdata[4] .. ") for" .. pa)
                    killblockdrop(pa, nil)
                end
            end

            -- captcha generator functions
            require "caphtml"
            displaycapd(pa)
            ngx.flush()
            ngx.exit(200)
        elseif (cookdata[2] == "cap_not_solved") then
            if (tonumber(cookdata[3]) + 60) > ngx.now() then
                killconnection(pa)
                ngx.header.content_type = "text/html"
                ngx.say("<h1>THINK OF WHAT YOU HAVE DONE!</h1>")
                ngx.say("<p>That captcha was generated just for you. And look at what you did. Ignoring the captcha... not even giving an incorrect answer to his meaningless existence. You couldn't even give him false hope. Shame on you.</p>")
                ngx.say("<p>Don't immediately refresh for a new captcha! Try and fail. You must now wait about a minute for a new captcha to load.</p>")
                ngx.flush()
                ngx.exit(200)
            end
            require "caphtml"
            displaycapd(pa)
            ngx.flush()
            ngx.exit(200)
        elseif (cookdata[2] == "captcha_solved") then
            if (tonumber(cookdata[3]) + session_timeout) < ngx.now() then
                require "caphtml"
                caperror = "Session expired"
                displaycapd(pa)
                ngx.flush()
                ngx.exit(200)
            end
        else
            ngx.log(ngx.ERR, "No matching cook type data but valid parse! Encryption break? Cookie (" .. field .. ") [" .. plaintext .. "] circuit: " .. pa)
            killblockdrop(pa, field)
        end
    end
end

if ngx.var.request_method == "POST" then
    --Will trigger under cookie loading error
    if err then
        sessionexpired()
    end

    if field ~= nil then
        plaintext = decrypt(field)
        if not plaintext then
            killblockdrop(pa, field)
        end
        cookdata = split(plaintext, "|")
        if (cookdata[2] == "queue") then
            killblockdrop(pa, field)
        elseif (cookdata[2] == "captcha_solved") then
            return
        elseif (cookdata[2] == "cap_not_solved") then
            require "caphtml"
            if (tonumber(cookdata[3]) + session_timeout) < ngx.now() then
                require "caphtml"
                caperror = "Session expired"
                displaycapd(pa)
                ngx.flush()
                ngx.exit(200)
            end

            cookdata = split(plaintext, "|")
            expiretime = tonumber(cookdata[3])
            if expiretime == nil or (tonumber(expiretime) + 60) < ngx.now() then
                caperror = "Captcha expired"
                displaycapd(pa)
                ngx.flush()
                ngx.exit(200)
            end

            -- resty has a library for parsing POST data but it's not really needed
            ngx.req.read_body()
            local dataraw = ngx.req.get_body_data()
            if dataraw == nil then
                caperror = "You didn't submit anything. Try again."
                displaycapd(pa)
                ngx.flush()
                ngx.exit(200)
            end

            if string.len(dataraw) > string.len(field) then
                    ngx.log(ngx.ERR, "CAPTCHA SOLVE POST: EXCESSIVELY LONG POST REQUEST (" .. field .. ") for" .. pa)
                    killblockdrop(pa, field)
                    ngx.flush()
                    ngx.exit(200)
            end
            data = split(dataraw, "&")
            local sentcap = ""
            local splitvalue = ""
            for index, value in ipairs(data) do
                if index > string.len(cookdata[5]) then
                    ngx.log(ngx.ERR, "CAPTCHA SOLVE POST: EXCESSIVELY LONG ANSWER POST FOR ANSWER (" .. cookdata[5] .. ") for" .. pa)
                    killblockdrop(pa, field)
                    break
                end
                splitvalue = split(value, "=")[2]
                if splitvalue == nil then
                    caperror = "You Got That Wrong. Try again"
                    displaycapd(pa)
                    ngx.flush()
                    ngx.exit(200)
                end
                sentcap = sentcap .. splitvalue
            end

            --in high levels of attack this system may make reachability of your service worse. But it protects against certain kinds of dcap caching attacks.
            if "no_proxy" ~= cookdata[4] then
                if pa ~= cookdata[4] then
                    ngx.log(ngx.ERR, "CAPTCHA SOLVE POST: Incorrect circuit id (" .. cookdata[4] .. ") for" .. pa)
                    killblockdrop(pa, field)
                end
            end

            if string.lower(sentcap) == string.lower(cookdata[5]) then
                --block valid sent cookies to prevent people from just sending the same solved solution over and over again
                blockcookies(field)
                cookdata[1] = random.token(random.number(5, 20))
                cookdata[2] = "captcha_solved"
                cookdata[3] = ngx.now()
                cookdata[6] = "0"
                local ciphertext = encrypt(table.concat(cookdata, "|"))
                local ok, err =
                    cookie:set(
                    {
                        key = "dcap",
                        value = ciphertext,
                        path = "/",
                        domain = ngx.var.host,
                        httponly = true,
                        max_age = session_timeout,
                        samesite = "Lax"
                    }
                )
                if not ok then
                    ngx.say("cookie error")
                    return
                end
                local redirect_to = ngx.var.uri
                if ngx.var.query_string ~= nil then
                    redirect_to = redirect_to .. "?" .. ngx.var.query_string
                end
                return ngx.redirect(redirect_to)
            else
                caperror = "You Got That Wrong. Try again"
            end
            displaycapd(pa)
            ngx.flush()
            ngx.exit(200)
        end
    else
        --Will trigger when cookie could be loaded but field isn't valid. Sanity check stuff.
        sessionexpired()
    end
end
