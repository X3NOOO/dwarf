<?php // Copyright (C) 2023 X3NO [https://github.com/X3NOOO] licensed under GNU AGPL 
function openDb(): SQLite3
{
    $db = new SQLite3("dwarf.sqlite");
    $db->enableExceptions(true);
    $err = $db->exec('CREATE TABLE IF NOT EXISTS urls (
        "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
        "short_url" TEXT NOT NULL,
        "long_url" TEXT NOT NULL,
        "dies_at" TEXT DEFAULT NULL,
        "password" TEXT DEFAULT NULL,
        "uses" INTEGER DEFAULT NULL
    )');
    if ($err === false) {
        throw new Exception($db->lastErrorMsg());
    }

    return $db;
}

function removeFromDb($db, $shortlink)
{
    $stmt = $db->prepare('DELETE FROM urls WHERE short_url = :short_url');
    if ($stmt === false) {
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':short_url', $shortlink, SQLITE3_TEXT);
    if ($stmt === false) {
        throw new Exception($db->lastErrorMsg());
    }
    $result = $stmt->execute();
    if ($result === false) {
        throw new Exception($db->lastErrorMsg());
    }
}

function getLonglink($db, $shortlink): string|bool
{
    $stmt = $db->prepare('SELECT * FROM urls WHERE short_url = :short_url');
    if ($stmt === false) {
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':short_url', $shortlink, SQLITE3_TEXT);
    if ($stmt === false) {
        throw new Exception($db->lastErrorMsg());
    }
    $result = $stmt->execute();
    if ($result === false) {
        throw new Exception($db->lastErrorMsg());
    }
    $row = $result->fetchArray();
    if ($row === false) {
        return false;
    }
    $long_url = $row['long_url'];

    // check if the entry is expired
    $dies_at = $row['dies_at'];
    $now = new DateTime();
    $dies_at = new DateTime($dies_at);
    if ($now > $dies_at) {
        try {
            removeFromDb($db, $shortlink);
        } catch (Exception $e) {
            http_response_code(500);
            echo "Internal server error: " . $e->getMessage();
        }

        return false;
    }

    // check if there are valid uses
    $uses = $row['uses'];
    if (!is_null($uses)) {
        if ($uses <= 0) {
            try {
                removeFromDb($db, $shortlink);
            } catch (Exception $e) {
                http_response_code(500);
                echo "Internal server error: " . $e->getMessage();
            }
            return false;
        } else {
            //decrement uses
            $stmt = $db->prepare('UPDATE urls SET uses = uses-1 WHERE short_url = :short_url');
            if ($stmt === false) {
                throw new Exception($db->lastErrorMsg());
            }
            $stmt->bindValue(':short_url', $shortlink, SQLITE3_TEXT);
            if ($stmt === false) {
                throw new Exception($db->lastErrorMsg());
            }
            $result = $stmt->execute();
            if ($result === false) {
                throw new Exception($db->lastErrorMsg());
            }
        }
    }
    $result->finalize();
    $stmt->close();
    $db->close();

    return $long_url;
}

function base62_encode($num): string
{
    $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $base = strlen($chars);
    $str = '';

    while ($num > 0) {
        $str = $chars[$num % $base] . $str;
        $num = (int) ($num / $base);
    }

    return $str;
}

function generateShortlink($db): string
{
    $result = $db->querySingle("SELECT MAX(id) FROM urls");
    if ($result) {
        $maxId = intval($result);
        $encoded = base62_encode($maxId);
        return '@' . $encoded; // user selected shortlinks cannot contain @ so by appending it here were sure that user wont create a collision by reserving the link wed want to use in the future
    }

    throw new Exception($db->lastErrorMsg());
}

function addNewShortlink($db, $shortlink, $long_url, $dies_at, $password, $uses)
{
    $stmt = $db->prepare('INSERT INTO urls (short_url, long_url, dies_at, password, uses) VALUES (:short_url, :long_url, :dies_at, :password, :uses)');
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':short_url', $shortlink, SQLITE3_TEXT);
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':long_url', $long_url, SQLITE3_TEXT);
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':dies_at', $dies_at, SQLITE3_TEXT);
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':password', $password, $password == "" ? SQLITE3_NULL : SQLITE3_TEXT);
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $stmt->bindValue(':uses', $uses, $uses == "" ? SQLITE3_NULL : SQLITE3_INTEGER);
    if ($stmt === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }
    $result = $stmt->execute();
    if ($result === false) {
        $db->close();
        throw new Exception($db->lastErrorMsg());
    }

    $result->finalize();
    $stmt->close();
    $db->close();
}

function getServerUrl(): string {
    $protocol = stripos($_SERVER['SERVER_PROTOCOL'], 'https') === 0 ? 'https://' : 'http://';
    return $protocol . $_SERVER['SERVER_NAME'];
}

// we got a creation request
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    try {
        $db = openDb();
    } catch (Exception $e) {
        http_response_code(500);
        echo "Internal server error: " . $e->getMessage();
        return;
    }
    $long_url = $_POST['long_url'];
    $shortlink = $_POST['shortlink'];
    $dies_at = $_POST['dies_at'];
    $password = $_POST['password'];
    $uses = $_POST['uses'];

    if ($password != "") {
        http_response_code(501);
        echo 'Passwords are not implemented yet.';
        $db->close();
        return;
    }

    if (!filter_var($long_url, FILTER_VALIDATE_URL) && !filter_var($long_url = 'http://' . $long_url, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        echo 'Invalid long link.';
        $db->close();
        return;
    }

    if ($shortlink == "") {
        try {
            $shortlink = generateShortlink($db);
        } catch (Exception $e) {
            http_response_code(500);
            echo "Internal server error: " . $e->getMessage();
            $db->close();
            return;
        }
    } else if (preg_match('/^[a-zA-Z0-9_-]+$/', $shortlink) == false) {
        http_response_code(400);
        echo 'Invalid shortlink selected.';
        $db->close();
        return;
    }

    try {
        $longlink = getLonglink($db, $shortlink);
        if ($longlink !== false) {
            http_response_code(400);
            echo 'This shortlink is already taken.';
            $db->close();
            return;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo "Internal server error: " . $e->getMessage();
        $db->close();
        return;
    }

    try {
        addNewShortlink($db, $shortlink, $long_url, $dies_at, $password, $uses);
    } catch (Exception $e) {
        http_response_code(500);
        echo "Internal server error: " . $e->getMessage();
        $db->close();
        return;
    }

    $db->close();

    $server = getServerUrl();
    echo $server . '/' . $shortlink;
    return;
}

$request = $_SERVER['REQUEST_URI'];
if ($request != '/' && $request != '' && $request != '/index.php' && $request != '/?not_found=true' && $request != '?not_found=true') {
    // shortened url
    try {
        $db = openDb();
    } catch (Exception $e) {
        http_response_code(500);
        echo "Internal server error: " . $e->getMessage();
    }
    $short_url = ltrim($request, '/');
    if (preg_match('/^@?[a-zA-Z0-9_-]+$/', $short_url) !== 1) {
        http_response_code(400);
        echo 'Invalid shortlink.';
        return;
    }
    try {
        $long_url = getLonglink($db, $short_url);
        if ($long_url === false) {
            header('Location: ' . getServerUrl() . '?not_found=true');
            return;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo "Internal server error: " . $e->getMessage();
        $db->close();
        return;
    }
    $db->close();
    header('Location: ' . $long_url);
} else if ($request === '/?not_found=true' || $request === '?not_found=true') {
    $notice = 'The shortlink you\'ve clicked does not exist.';
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>dwarf - an url shortener</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="branding">
        <h2>dwarf</h2>
        <h3>an url shortener</h3>
    </div>
    <div class="generator">
        <div id="notice"><?=$notice?></div>
        <form id="request_form" action="<?= $_SERVER['PHP_SELF']; ?>" method="POST">
            <input type="text" name="long_url" id="long_url" placeholder="Enter a long link">
            <button type="submit" name="submit">Shorten</button>
            <br>
            <input type="text" name="shortlink" id="shortlink" placeholder="Custom link">
            <span id="info_shortlink"
                title="The letters after the link. The shortlink should only use following characters: a-z, A-Z, 0-9, _, -.">?</span>
            <br>
            <div id="advanced_menu_opener" class="open_collapsible">Show advanced options ></div>
            <div id="advanced_menu" class="collapsible">
                <input type="checkbox" id="enable_uses">
                Number of uses:
                <input type="number" name="uses" id="uses" placeholder="1" disabled>
                <span id="info_number" title="The shortened link will be deleted after this many uses.">?</span>
                <br>

                <input type="checkbox" id="enable_dies_at">
                Expires:
                <input type="date" name="dies_at" id="dies_at" placeholder="Expires at" disabled>
                <span id="info_dies_at" title="The shortened link will be deleted by this date.">?</span>
                <br>

                <input type="checkbox" id="enable_password">
                Password:
                <input type="password" name="password" id="password" placeholder="Password" disabled>
                <span id="info_password"
                    title="If you use password your original link will get encrypted. There will be no way of recovering the original link if you forget the password.">?</span>
            </div>
        </form>
        <span id="result">
            <div id="success"></div>
            <div id="failure"></div>
            <button id="copy_result">Copy shortlink</button>
        </span>
        <div class="footer">
            dwarf is opensource, you can grab a copy <a href="https://github.com/X3NOOO/dwarf" target="_blank">here</a>
        </div>
    </div>
    <script>
        document.getElementById("request_form").addEventListener("submit", element => {
            element.preventDefault();
            const success = document.getElementById("success");
            const failure = document.getElementById("failure");
            const copy_button = document.getElementById("copy_result");
            success.style.display = "none";
            failure.style.display = "none";
            copy_button.style.display = "none";

            let formData = new FormData(element.currentTarget);

            fetch("<?= $_SERVER['PHP_SELF']; ?>", {
                method: "POST",
                body: formData
            })
                .then(response => {
                    if (!response.ok) {
                        return response.text().then(text => {
                            throw new Error(text);
                        });
                    }
                    return response.text();
                })
                .then(data => {
                    // console.log(data);
                    success.style.display = "block";
                    copy_button.style.display = "block";
                    success.innerHTML = "<a href='" + data + "' target='_blank'>" + data + "</a>";
                })
                .catch(error => {
                    // console.error(error);
                    failure.style.display = "block";
                    // copy_button.style.display = "block";
                    failure.innerText = error.message;
                });
        })

        // disable input to dies_at and password if their checkbox are not checked
        document.querySelectorAll("[id^=enable_]").forEach(element => {
            element.addEventListener("change", function (e) {
                if (this.checked) {
                    document.getElementById(element.id.replace("enable_", "")).disabled = false;
                } else {
                    document.getElementById(element.id.replace("enable_", "")).disabled = true;
                }
            })
        });

        // collapsible advanced menu
        let menu_hidden = true;
        document.getElementById("advanced_menu_opener").addEventListener("click", element => {
            menu_hidden = !menu_hidden;

            element.currentTarget.innerText = element.currentTarget.innerText.replace(menu_hidden ? 'V' : '>', menu_hidden ? '>' : 'V');

            document.getElementById("advanced_menu").style.display = menu_hidden ? "none" : "block";
        });

        // copy button
        document.getElementById("copy_result").addEventListener("click", function () {
            const container = document.getElementById("result");
            const divs = container.getElementsByTagName("div");
            let text = "";

            for (let div of divs) {
                if (getComputedStyle(div).display !== "none") {
                    text = div.innerText;
                    break;
                }
            }

            // Copy the text to clipboard
            if (text) {
                const textarea = document.createElement("textarea");
                document.body.appendChild(textarea);
                textarea.value = text;
                textarea.select();
                document.execCommand("copy");
                document.body.removeChild(textarea);
                
                const prev = this.innerText;
                this.innerText = "Copied!";

                setTimeout(() => {
                    this.innerText = prev;
                }, 2000);
            }
        });

        // check if notice exists
        window.addEventListener("load", () => {
            const notice = document.getElementById("notice");
            if(notice.innerText != "") {
                notice.style.display = "block";
            }
        })
    </script>
</body>

</html>