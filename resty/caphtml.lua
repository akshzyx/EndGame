function displaycapd(pa)
    ngx.header.content_type = "text/html"
    local cookie, err = cook:new()
    if not cookie then
        ngx.log(ngx.ERR, err)
        ngx.say("cookie error")
        ngx.exit(200)
    end

    local blocked_cookies = ngx.shared.blocked_cookies
    local field, err = cookie:get("dcap")
    plaintext = decrypt(field)
    cookdata = split(plaintext, "|")

    if (cookdata[2] == "cap_not_solved") then
        if (cookdata[6] == "3") then
            blocked_cookies:set(field, 1, 120)
            local ni = random.number(5,20)
            local tstamp = ngx.now() + ni
            local plaintext = random.token(random.number(5, 20)) .. "|queue|" .. tstamp .. "|" .. pa .. "|"
            local ciphertext = encrypt(plaintext)
            cookie:set(
            {
                key = "dcap",
                value = ciphertext,
                path = "/",
                domain = ngx.var.host,
                httponly = true,
                max_age = 30,
                samesite = "Lax"
            })
            ngx.header["Refresh"] = ni
            ngx.header.content_type = "text/html"
            local file = io.open("/etc/nginx/resty/queue.html")
            local queue, err = file:read("*a")
            file:close()
            ngx.say(queue)
            ngx.flush()
            ngx.exit(200)
        end
    end

    local function getChallenge()
        local success, module = pcall(require, "challenge")
        if not success then
            ngx.header["Refresh"] = '5'
            ngx.say("Captcha racetime condition hit. Refreshing in 5 seconds.")
            ngx.exit(200)
        end
        local ni = random.number(0,49)
        if challengeArray[ni] ~= nil then
            local challenge = challengeArray[ni]
            return split(challenge, "*")
        else
            ngx.header["Refresh"] = '5'
            ngx.say("Captcha racetime condition hit. Refreshing in 5 seconds.")
            ngx.exit(200)
        end
    end

    local im = getChallenge()
    local challengeStyle = im[1]
    local challengeAnswer = im[2]
    local challengeImage = im[3]

    local tstamp = ngx.now()
    local newcookdata = random.token(random.number(5, 20)) .. "|cap_not_solved|" .. tstamp .. "|" .. pa .. "|" .. challengeAnswer

    if (cookdata[2] == "queue") then
        newcookdata = newcookdata .. "|1"
    else
        newcookdata = newcookdata .. "|" .. tonumber(cookdata[6] + 1)
    end
    local ciphertext = encrypt(newcookdata)
    local ok, err =
        cookie:set(
        {
            key = "dcap",
            value = ciphertext,
            path = "/",
            domain = ngx.var.host,
            httponly = true,
            samesite = "Lax"
        }
    )

    blocked_cookies:set(field, 1, 120)

    if not ok then
        ngx.say("cookie error")
        ngx.exit(200)
    end

ngx.say([[<!DOCTYPE html>
    <html lang=en>
    <head>
    <title>DDOS Protection</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link id="favicon" rel="shortcut icon" href="FAVICON">
    </head><body><style>]])

    local file = io.open("/etc/nginx/resty/cap_d.css")

    if not file then
        ngx.exit(500)
    end

    local css, err = file:read("*a")

    file:close()

    ngx.say(css)

    ngx.say(challengeStyle)

ngx.say([[</style>
    <div class="container">
        <div class="left">
            <div class="networkLogo slide-right-ani">
                <div class="square"></div>
            <div class="text">
                    <span>SITENAME</span>
                    <div class="sm">network</div>
                </div>
            </div>
            <div class="cont">
                <div class="serviceLogo slide-right-ani">
                    <div class="square"></div>
                    <div class="text">SITENAME</div>
                </div>
                <div class="tagline slide-right-ani">SITETAGLINE</div>
                <div class="since slide-right-ani">since SITESINCE</div>
            </div>
        </div>
    <div class="inner">]])
    if caperror ~= nil then
        ngx.say('<p class="slide-left-ani alert"><strong>' .. caperror .. '</strong></p>')
    else
        ngx.say('<p class="slide-left-ani">Select each text box and enter the letter or number you see within the circle below.</p>')
    end
    ngx.say([[<form class="ddos_form slide-left-ani" method="post">
        <div class="input-box">
        <input class="ch" type="text" name="c1" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off" autofocus>]])
    for i = 2, 6, 1 do
        ngx.say('<input class="ch" type="text" name="c' .. i .. '" maxlength="1" pattern="[A-Za-z0-9]" autocomplete="off">')
    end
    ngx.say('<div class="image" style="background-image:url(data:image/webp;base64,' .. challengeImage .. ');"></div>')
ngx.say([[</div>
        <div class="expire">
            <div class="timer">
                <div class="time-part-wrapper">
                    <div class="time-part seconds tens">
                        <div class="digit-wrapper">
                            <span class="digit">0</span>
                            <span class="digit">5</span>
                            <span class="digit">4</span>
                            <span class="digit">3</span>
                            <span class="digit">2</span>
                            <span class="digit">1</span>
                            <span class="digit">0</span>
                        </div>
                    </div>
                    <div class="time-part seconds ones">
                        <div class="digit-wrapper">
                            <span class="digit">0</span>
                            <span class="digit">9</span>
                            <span class="digit">8</span>
                            <span class="digit">7</span>
                            <span class="digit">6</span>
                            <span class="digit">5</span>
                            <span class="digit">4</span>
                            <span class="digit">3</span>
                            <span class="digit">2</span>
                            <span class="digit">1</span>
                            <span class="digit">0</span>
                        </div>
                    </div>
                </div>
                <div class="time-part-wrapper">
                    <div class="time-part hundredths tens">
                        <div class="digit-wrapper">
                            <span class="digit">0</span>
                            <span class="digit">9</span>
                            <span class="digit">8</span>
                            <span class="digit">7</span>
                            <span class="digit">6</span>
                            <span class="digit">5</span>
                            <span class="digit">4</span>
                            <span class="digit">3</span>
                            <span class="digit">2</span>
                            <span class="digit">1</span>
                            <span class="digit">0</span>
                        </div>
                    </div>
                    <div class="time-part hundredths ones">
                        <div class="digit-wrapper">
                            <span class="digit">0</span>
                            <span class="digit">9</span>
                            <span class="digit">8</span>
                            <span class="digit">7</span>
                            <span class="digit">6</span>
                            <span class="digit">5</span>
                            <span class="digit">4</span>
                            <span class="digit">3</span>
                            <span class="digit">2</span>
                            <span class="digit">1</span>
                            <span class="digit">0</span>
                        </div>
                    </div>
                </div>
            </div>
        </div><button class="before" type="submit">Submit</button>
        <button class="expired" type="submit"> Refresh (expired)</button>
        </form>
        </div>
        </div>
    </body>
</html>]])
--if you need the answer right away for testing
--ngx.say(challengeAnswer)
end
