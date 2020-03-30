<?php
/**
 * Created by PhpStorm.
 * User: zdb
 * Date: 2020/3/26
 * Time: 18:37
 * Description:
 */
namespace app\app_api\controller;
use service\TokenService;
use service\Json;
use service\JsonService;
use service\UtilService;
use think\Cache;
use think\Controller;
use think\Request;
use services\MiniProgramService;
use app\app_api\model\user\WechatUser;
class Login extends Controller{

    /**
     * code换取session_key
     */
    public function setCode(){
        list($code) = UtilService::postMore([['code', '']], $request, true);//获取前台传的code
        if ($code == '') return Json::fail('参数错误');
        try{
            $userInfo = MiniProgramService::getUserInfo($code);
        }catch (\Exception $e){
            return Json::fail('获取session_key失败，请检查您的配置！',['line'=>$e->getLine(),'message'=>$e->getMessage()]);
        }
        $cache_key = md5(time().$code);
        if (isset($userInfo['session_key'])){
            Cache::set('yc_api_code_'.$cache_key, $userInfo['session_key'], 86400);
            return Json::successful(['cache_key'=>$cache_key]);
        }else
            return Json::fail('获取会话密匙失败');
    }
    /**
     * 小程序授权登录
     */
    public function login(Request $request)
    {
        $data = UtilService::postMore([
            ['iv', ''],
            ['encryptedData', ''],
            ['cache_key',''],
            ['spid',0],//推广人id
            ['code',''],//扫码进小程序的二维码id
        ]);
        $data['session_key']=Cache::get('eb_api_code_'.$data['cache_key']);
        if(!$data['cache_key'] || !$data['encryptedData'] || !$data['iv']) return Json::fail('参数错误');
        try{
            //解密获取用户信息
            $userInfo = MiniProgramService::encryptor($data['session_key'], $data['iv'], $data['encryptedData']);
        }catch (\Exception $e){
            return Json::status('410','获取会话密匙失败');
        }
        if(!isset($userInfo['openId'])) return Json::fail('openid获取失败');
        if(!isset($userInfo['unionId']))  $userInfo['unionId'] = '';
        $userInfo['session_key'] = $data['session_key'];
        $userInfo['spid'] = $data['spid'];
        $userInfo['code'] = $data['code'];
        $dataOauthInfo = WechatUser::routineOauth($userInfo);
        $userInfo['uid'] = $dataOauthInfo['uid'];
        $userInfo['page'] = $dataOauthInfo['page'];
        $userInfo['token'] = TokenService::getToken($userInfo['uid'],$userInfo['openId']);
        if($userInfo['token']===false) return Json::fail('获取用户访问token失败!');
        $userInfo['status'] = WechatUser::isUserStatus($userInfo['uid']);//用户状态
        return Json::successful($userInfo);
    }

}