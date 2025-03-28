<?php
//セッション開始
session_start();

//セッションの有効期限を設定（1週間に設定）
session_set_cookie_params(60 * 60 * 24 * 7);

//セッションクッキーに HttpOnly フラグと Secure フラグを設定
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);

//HTTPSの強制
if (empty($_SERVER['HTTPS'])) {
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit;
}

//ログインしているかを確認
if (isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

//クロスサイトリクエストフォージェリ (CSRF) 対策
//フォームにはトークンを埋め込む
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['token']) || $_POST['token'] !== $_SESSION['token']) {
        //トークンが一致しない場合はエラー
        $error_message = '不正なリクエストです。';
        redirect($error_message);
    }
} else {
    //トークンを生成
    $token = bin2hex(random_bytes(32));
    $_SESSION['token'] = $token;
}

//エラーメッセージを格納する変数
$error_message = null;
//クロスサイトスクリプティング (XSS) 対策
// error_messageを取得し、表示する
$error_message = $_GET['error_message'] ?? null;
if ($error_message) {
    $error_message_echo = '<p>' . htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8') . '</p>';
}
?>
<!DOCTYPE html>
<html lang="ja">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>サインアップ</title>
    <link rel="stylesheet" href="bin/login.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
</head>

<body>
    <form action="auth.php" method="post">
        <input type="hidden" name="action" value="regist">
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="hidden" name="g-recaptcha-response" id="recaptchaResponse">

        <div class="login-wrapper">
            <div class="login-form">
                <div class="login-header">
                    <div class="logo"><img
                            src="https://tensandev.github.io/image/%E3%82%A2%E3%82%A4%E3%82%B3%E3%83%B3.webp"
                            lat="firebase"></div>
                    <h1>サインアップ</h1>
                    <?php echo $error_message_echo; ?>
                    <p id="password_confirm_alert"></p>
                </div>
                <div class="input-field">
                    <div class="input-icon svg-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5"
                            stroke="currentColor" class="size-6">
                            <path stroke-linecap="round" stroke-linejoin="round"
                                d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
                        </svg>

                    </div>
                    <input type="email" placeholder="メールアドレス" name="email">
                </div>
                <div class="input-field">
                    <div class="input-icon svg-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5"
                            stroke="currentColor" class="size-6">
                            <path stroke-linecap="round" stroke-linejoin="round"
                                d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                        </svg>

                    </div>
                    <input type="password" placeholder="パスワード" name="password">
                </div>
                <div class="input-field">
                    <div class="input-icon svg-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5"
                            stroke="currentColor" class="size-6">
                            <path stroke-linecap="round" stroke-linejoin="round"
                                d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                        </svg>

                    </div>
                    <input type="password" placeholder="確認用のパスワード" name="password_confirm">
                </div>
                <button class="primary-button">登録</button>
                <div class="separator">または</div>
                <button class="google-button">
                    <img src="https://www.gstatic.com/marketing-cms/assets/images/d5/dc/cfe9ce8b4425b410b49b7f2dd3f3/g.webp=s48-fcrop64=1,00000000ffffffff-rw"
                        alt="Google Logo">
                    Googleでサインアップ
                </button>
                <div class="signup-link">
                    アカウントをお持ちですか？<a href="login.php">ログイン</a>
                </div>
            </div>
        </div>
    </form>
    <!--Google reCAPTCHA v3の挿入-->
    <script src="https://www.google.com/recaptcha/api.js?render=sitekey_here"></script>
    <script>
        grecaptcha.ready(function () {
            grecaptcha.execute('sitekey_here', { action: 'submit' }).then(function (token) {
                var recaptchaResponse = document.getElementById('recaptchaResponse');
                recaptchaResponse.value = token;
            });
        });
    </script>

</body>

</html>