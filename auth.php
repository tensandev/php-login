<?php
require_once 'database.php';

//functionでerror_messageを取得し、ここでリダイレクトする
function redirect($error_message)
{
    // クロスサイトスクリプティング（XSS）対策としてエスケープ処理
    $encoded_error_message = urlencode($error_message);
    // リダイレクト先が自分のサイト内かをチェック
    if (parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) !== $_SERVER['HTTP_HOST']) {
        // リダイレクト元が自分のサイト外の場合はエラーメッセージを表示
        echo '無効なリクエストです。<br/>リダイレクト元が不正です。';
    }
    if ($_POST['action'] == 'regist') {
        header("location: regist.php?error_message={$encoded_error_message}");
    } elseif ($_POST['action'] == 'login') {
        header("location: login.php?error_message={$encoded_error_message}");
    } elseif ($_POST['action'] == 'logout') {
        header("location: login.php?error_message={$encoded_error_message}");
    } else {
        //例外処理
        header("location: login.php?error_message={$encoded_error_message}");
    }
    exit();
}

// セッションを開始
session_start();

// セッションの有効期限を設定（1週間に設定）
session_set_cookie_params(60 * 60 * 24 * 7);

// セッションクッキーに HttpOnly フラグと Secure フラグを設定
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);

//HTTPSの強制
if (empty($_SERVER['HTTPS'])) {
    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit;
}

// クロスサイトリクエストフォージェリ (CSRF) 対策
// フォームにはトークンを埋め込む
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['token']) || $_POST['token'] !== $_SESSION['token']) {
        // トークンが一致しない場合はエラー
        $error_message = '不正なリクエストです。';
        redirect($error_message);
    }
} else {
    // トークンを生成
    $token = bin2hex(random_bytes(32));
    $_SESSION['token'] = $token;
}

// エラーメッセージを格納する変数
$error_message = null;

// Google reCAPTCHA v3 のサイトキーとシークレットキー
$recaptcha_site_key = 'site_key_here';
$recaptcha_secret_key = 'secret_key_here';

// reCAPTCHA の検証閾値（0.0 〜 1.0）
$recaptcha_threshold = 0.5;

// reCAPTCHA のトークンを取得
$recaptcha_token = $_POST['g-recaptcha-response'] ?? null;

// Google reCAPTCHA の検証
function verify_recaptcha($recaptcha_token, $recaptcha_secret_key, $recaptcha_threshold)
{
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $recaptcha_secret_key,
        'response' => $recaptcha_token,
    ];
    $options = [
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/x-www-form-urlencoded',
            'content' => http_build_query($data),
        ],
    ];
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $result = json_decode($result, true);

    if ($result['success'] && $result['score'] >= $recaptcha_threshold) {
        return true;
    } else {
        return false;
    }
}

// reCAPTCHA の検証
if (!verify_recaptcha($recaptcha_token, $recaptcha_secret_key, $recaptcha_threshold)) {
    redirect('reCAPTCHA の検証に失敗しました。');
}

// エラーが発生した場合に表示する設定　※本番環境では非表示にすること
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// フォームからPOSTされたデータがあるか確認
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($_POST['action'] == 'regist') {
        // ユーザー登録処理
        // メールアドレスとパスワードを取得
        $email = $_POST['email'] ?? null;
        $password = $_POST['password'] ?? null;
        //正規表現でメールアドレスの形式をチェック
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            redirect('メールアドレスの形式が正しくありません。');
        } elseif (strlen($password) < 8) {
            // パスワードが8文字未満の場合はエラー
            // ※ここでパスワードの強度をチェックする
            // ※記号（!?以外にもほかにもあるのでarrayでリストアップ）や大文字小文字のアルファベット、数字が含まれているかをチェック
            $special_chars = ['!', '?', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', ':', ';', '<', '>', ',', '.', '~',];
            if (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password) || !preg_match('/[' . preg_quote(implode('', $special_chars), '/') . ']/', $password)) {
                // パスワードが強度不足の場合はエラー
                redirect('パスワードは大文字小文字のアルファベット、数字、記号をそれぞれ1文字以上含めてください。');
            }
        } else {
            // メールアドレスが登録済みかチェック
            $sql = 'SELECT * FROM users WHERE email = :email';
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch();
            if ($user) {
                // メールアドレスが登録済みの場合はエラー
                redirect('メールアドレスが既に登録されています。');
            }
        }
        // ユーザー登録処理
        // パスワードをハッシュ化
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        // ユーザーを登録
        $sql = 'INSERT INTO users (user_id, email, password) VALUES (:email, :password)';
        $stmt = $pdo->prepare($sql);
        // user_idはUUIDを生成して設定する
        $user_id = bin2hex(random_bytes(16));
        $stmt->bindParam(':user_id', $user_id, PDO::PARAM_STR);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->bindParam(':password', $password_hash, PDO::PARAM_STR);
        $stmt->execute();
        //登録されたかもう一度確認する
        $sql = 'SELECT * FROM users WHERE email = :email';
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        $user = $stmt->fetch();
        if (!$user) {
            // ユーザー登録に失敗した場合はエラー
            redirect('ユーザー登録に失敗しました。システム管理者にお問い合わせください。');
        }
        // 成功ページにリダイレクト
        header('location: regist_success.html');
        exit;

    } elseif ($_POST['action'] == 'login') {
        // ログイン処理
        // メールアドレスとパスワードを取得
        $email = $_POST['email'] ?? null;
        $password = $_POST['password'] ?? null;
        // メールアドレスが登録されているかチェック
        $sql = 'SELECT * FROM users WHERE email = :email';
        $stmt = $pdo->prepare($sql);
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        $user = $stmt->fetch();
        if (!$user) {
            // メールアドレスが登録されていない場合はエラー
            redirect('メールアドレスまたはパスワードが間違っています。');
        } elseif (!password_verify($password, $user['password'])) {
            // パスワードが間違っている場合はエラー
            //ブルートフォース攻撃対策
            //ログイン失敗回数を取得
            $sql = 'SELECT * FROM login_attempts WHERE email = :email';
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            //ログイン失敗回数が0回の場合は新規登録
            if ($stmt->rowCount() == 0) {
                //ログイン失敗回数を1回に設定 ※初回の失敗時
                $sql = 'INSERT INTO login_attempts (email, count) VALUES (:email, 1)';
                $stmt = $pdo->prepare($sql);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->execute();
            } else {
                $login_attempts = $stmt->fetch();
                //ログイン失敗回数が10回以上の場合はエラー
                if ($login_attempts['count'] >= 10) {
                    redirect('アカウントがロックダウンされました。1時間後に再度お試しください。');
                } else {
                    //ログイン失敗回数を1回増やす ※2回目以降の失敗時
                    $count = $login_attempts['count'] + 1;
                    $sql = 'UPDATE login_attempts SET count = :count WHERE email = :email';
                    $stmt = $pdo->prepare($sql);
                    $stmt->bindParam(':count', $count, PDO::PARAM_INT);
                    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                    $stmt->execute();
                }
            }
            redirect('メールアドレスまたはパスワードが間違っています。');
        } else {
            //ブルートフォース攻撃対策
            //ログイン失敗回数を取得
            $sql = 'SELECT * FROM login_attempts WHERE email = :email';
            $stmt = $pdo->prepare($sql);
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            $login_attempts = $stmt->fetch();
            //ログイン失敗回数が10回以上の場合はエラー
            if ($login_attempts['count'] >= 10) {
                redirect('アカウントがロックダウンされました。1時間後に再度お試しください。');
            } else {
                // ログイン成功時の処理
                // ユーザー情報をセッションに保存
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['email'] = $user['email'];
                // ログイン成功後に session_regenerate_id(true) を呼び出してセッション ID を再生成
                session_regenerate_id(true);
                //ログインログに記録
                $sql = 'INSERT INTO login_logs (user_id, email, ip_address) VALUES (:user_id, :email, :ip_address)';
                $stmt = $pdo->prepare($sql);
                $stmt->bindParam(':user_id', $user['id'], PDO::PARAM_INT);
                $stmt->bindParam(':email', $user['email'], PDO::PARAM_STR);
                $stmt->bindParam(':ip_address', $_SERVER['REMOTE_ADDR'], PDO::PARAM_STR);
                $stmt->execute();
                //ログイン失敗回数を0回に設定
                $sql = 'UPDATE login_attempts SET count = 0 WHERE email = :email';
                $stmt = $pdo->prepare($sql);
                $stmt->bindParam(':email', $email, PDO::PARAM_STR);
                $stmt->execute();
                // メインページにリダイレクト
                // ※ログイン後のページに変更がある場合はPOSTで送信したページにリダイレクトする
                if (isset($_POST['redirect'])) {
                    // リダイレクト先が指定されている場合はそのページにリダイレクト
                    header("location: {$_POST['redirect']}");
                } else {
                    // リダイレクト先が指定されていない場合はメインページにリダイレクト
                    header('location: index.php');
                }
                exit;
            }

        }

    } elseif ($_POST['action'] == 'logout') {
        // ログアウト処理
        // セッション変数を全て解除
        $_SESSION = [];
        // セッションを破棄
        session_destroy();
        // ログインページにリダイレクト
        redirect('ログアウトしました。');
    } else {
        //例外処理
        $error_message = '不正なリクエストです。';
    }
}
