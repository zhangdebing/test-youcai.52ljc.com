<?php
/**
 * Created by PhpStorm.
 * User: zdb
 * Date: 2020/3/26
 * Time: 18:37
 * Description:
 */
namespace app\app_api\controller;
use service\JsonService;
use service\UtilService;
use think\Cache;
use think\Controller;
use think\Request;
use services\MiniProgramService;
use EasyWeChat\MiniProgram\Sns\Sns;
class Login extends Controller{

    /**
     * 小程序授权登录
     */
    public function mp_auth(Request $request)
    {
        $cache_key = '';
        list($code, $post_cache_key, $login_type) = UtilService::postMore([
            ['code', ''],
            ['cache_key', ''],
            ['login_type', '']
        ], $request, true);
        $session_key = Cache::get('eb_api_code_' . $post_cache_key);
        if (!$code && !$session_key)
            return JsonService::fail('授权失败,参数有误');
        if ($code && !$session_key) {
            try {
                $userInfoCong = MiniProgramService::getUserInfo($code);
                $session_key = $userInfoCong['session_key'];
                $cache_key = md5(time() . $code);
                Cache::set('eb_api_code_' . $cache_key, $session_key, 86400);
            } catch (\Exception $e) {
                return app('json')->fail('获取session_key失败，请检查您的配置！', ['line' => $e->getLine(), 'message' => $e->getMessage()]);
            }
        }

        $data = UtilService::postMore([
            ['spread_spid', 0],
            ['spread_code', ''],
            ['iv', ''],
            ['encryptedData', ''],
        ]);//获取前台传的code
        try {
            //解密获取用户信息
            $userInfo = MiniProgramService::encryptor($session_key, $data['iv'], $data['encryptedData']);
        } catch (\Exception $e) {
            if ($e->getCode() == '-41003') return app('json')->fail('获取会话密匙失败');
        }
        if (!isset($userInfo['openId'])) return app('json')->fail('openid获取失败');
        if (!isset($userInfo['unionId'])) $userInfo['unionId'] = '';
        $userInfo['spid'] = $data['spread_spid'];
        $userInfo['code'] = $data['spread_code'];
        $userInfo['session_key'] = $session_key;
        $userInfo['login_type'] = $login_type;
        $uid = WechatUser::routineOauth($userInfo);
        $userInfo = User::where('uid', $uid)->find();
        if ($userInfo->login_type == 'h5' && ($h5UserInfo = User::where(['account' => $userInfo->phone, 'phone' => $userInfo->phone, 'user_type' => 'h5'])->find()))
            $token = UserToken::createToken($userInfo, 'routine');
        else
            $token = UserToken::createToken($userInfo, 'routine');
        if ($token) {
            event('UserLogin', [$userInfo, $token]);
            return app('json')->successful('登陆成功！', [
                'token' => $token->token,
                'userInfo' => $userInfo,
                'expires_time' => strtotime($token->expires_time),
                'cache_key' => $cache_key
            ]);
        } else
            return app('json')->fail('获取用户访问token失败!');
    }

}