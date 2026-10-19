//! User-agent classification: bot, OS, device, browser — keyword based,
//! no external databases. Ordering matters: bots first, Edge before Chrome,
//! iOS/Android before desktop OSes.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub bot: String, // "" if not a bot, else e.g. "Googlebot"
    pub os: String,
    pub device: String, // Desktop | Mobile | Tablet
    pub browser: String,
}

const BOTS: &[(&str, &str)] = &[
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("bingpreview", "Bing Preview"),
    ("slurp", "Yahoo Slurp"),
    ("duckduckbot", "DuckDuckGo Bot"),
    ("yandex", "Yandex"),
    ("baiduspider", "Baiduspider"),
    ("sogou", "Sogou"),
    ("semrushbot", "Semrush Bot"),
    ("ahrefsbot", "Ahrefs Bot"),
    ("mj12bot", "MJ12 Bot"),
    ("dotbot", "Dotbot"),
    ("rogerbot", "Rogerbot"),
    ("facebookexternalhit", "Facebook"),
    ("facebot", "Facebook"),
    ("twitterbot", "Twitter"),
    ("linkedinbot", "LinkedIn"),
    ("pinterest", "Pinterest"),
    ("telegrambot", "Telegram Bot"),
    ("slackbot", "Slack Bot"),
    ("discordbot", "Discord Bot"),
    ("whatsapp", "WhatsApp"),
    ("headlesschrome", "Headless Chrome"),
    ("curl", "curl"),
    ("wget", "wget"),
    ("python-requests", "Python-requests"),
    ("python-urllib", "Python-urllib"),
    ("go-http-client", "Go-http-client"),
    ("java/", "Java"),
    ("httpclient", "Apache HttpClient"),
    ("okhttp", "OkHttp"),
    ("libwww-perl", "libwww-perl"),
    ("lwp::simple", "libwww-perl"),
    ("scrapy", "Scrapy"),
    ("zgrab", "Zgrab"),
    ("masscan", "Masscan"),
    ("zgrab2", "Zgrab"),
    ("nmap", "Nmap"),
    ("crawler", "Crawler"),
    ("spider", "Spider"),
    ("bot", "Bot"),
];

pub fn classify(ua: &str) -> Client {
    let lower = ua.to_ascii_lowercase();

    // 1. bots
    for (needle, name) in BOTS {
        if lower.contains(needle) {
            return Client {
                bot: name.to_string(),
                os: "Bot".to_string(),
                device: "Bot".to_string(),
                browser: name.to_string(),
            };
        }
    }

    // 2. OS
    let os = if lower.contains("windows") || lower.contains("win32") || lower.contains("win64") {
        "Windows"
    } else if lower.contains("android") {
        "Android"
    } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ipod") {
        "iOS"
    } else if lower.contains("mac os x") || lower.contains("macintosh") || lower.contains("mac_os")
    {
        "macOS"
    } else if lower.contains("cros") || lower.contains("crkey") {
        "Chrome OS"
    } else if lower.contains("linux") {
        "Linux"
    } else if lower.contains("freebsd") {
        "FreeBSD"
    } else if lower.contains("playstation") {
        "PlayStation"
    } else if lower.contains("xbox") {
        "Xbox"
    } else if lower.contains("blackberry") || lower.contains("rim tablet") {
        "BlackBerry"
    } else if lower.contains("windows phone") {
        "Windows Phone"
    } else {
        "Other"
    };

    // 3. device
    let device = if lower.contains("ipad") || lower.contains("tablet") || lower.contains("xoom") {
        "Tablet"
    } else if lower.contains("iphone")
        || lower.contains("ipod")
        || lower.contains("android")
        || lower.contains("mobile")
        || lower.contains("opera mini")
        || lower.contains("windows phone")
        || lower.contains("blackberry")
    {
        "Mobile"
    } else {
        "Desktop"
    };

    // 4. browser (priority order: Edge -> Opera -> Samsung -> IE -> Chromium -> Chrome -> Safari -> Firefox)
    let browser = if lower.contains("edg/") || lower.contains("edgios") || lower.contains("edga/") {
        "Edge"
    } else if lower.contains("opr/") || lower.contains("opera") {
        "Opera"
    } else if lower.contains("samsungbrowser") {
        "Samsung Internet"
    } else if lower.contains("trident") || lower.contains("msie") {
        "Internet Explorer"
    } else if lower.contains("chromium") {
        "Chromium"
    } else if lower.contains("crios") || lower.contains("fxios") {
        if lower.contains("crios") {
            "Chrome (iOS)"
        } else {
            "Firefox (iOS)"
        }
    } else if lower.contains("chrome") || lower.contains("crmo") {
        "Chrome"
    } else if lower.contains("safari") {
        "Safari"
    } else if lower.contains("firefox") {
        "Firefox"
    } else {
        "Other"
    };

    Client {
        bot: String::new(),
        os: os.to_string(),
        device: device.to_string(),
        browser: browser.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn googlebot() {
        let c =
            classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert_eq!(c.bot, "Googlebot");
        assert_eq!(c.device, "Bot");
    }

    #[test]
    fn bingbot() {
        let c = classify("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)");
        assert_eq!(c.bot, "Bingbot");
    }

    #[test]
    fn curl_is_bot() {
        let c = classify("curl/7.68.0");
        assert_eq!(c.bot, "curl");
    }

    #[test]
    fn safari_on_iphone() {
        let c = classify("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
        assert_eq!(c.browser, "Safari");
        assert_eq!(c.os, "iOS");
        assert_eq!(c.device, "Mobile");
        assert_eq!(c.bot, "");
    }

    #[test]
    fn chrome_on_android() {
        let c = classify("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36");
        assert_eq!(c.browser, "Chrome");
        assert_eq!(c.os, "Android");
        assert_eq!(c.device, "Mobile");
    }

    #[test]
    fn edge_on_windows() {
        let c = classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.61");
        assert_eq!(c.browser, "Edge");
        assert_eq!(c.os, "Windows");
        assert_eq!(c.device, "Desktop");
    }

    #[test]
    fn ie11() {
        let c = classify("Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko");
        assert_eq!(c.browser, "Internet Explorer");
        assert_eq!(c.os, "Windows");
    }

    #[test]
    fn firefox_macos() {
        let c = classify(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0",
        );
        assert_eq!(c.browser, "Firefox");
        assert_eq!(c.os, "macOS");
    }

    #[test]
    fn opera() {
        let c = classify("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0");
        assert_eq!(c.browser, "Opera");
    }

    #[test]
    fn ipad_is_tablet() {
        let c = classify("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
        assert_eq!(c.device, "Tablet");
        assert_eq!(c.os, "iOS");
    }

    #[test]
    fn empty_ua() {
        let c = classify("");
        assert_eq!(c.browser, "Other");
        assert_eq!(c.os, "Other");
        assert_eq!(c.device, "Desktop");
        assert_eq!(c.bot, "");
    }

    #[test]
    fn generic_bot() {
        let c = classify("SomeRandomCrawler/1.0");
        assert_eq!(c.bot, "Crawler");
    }
}
