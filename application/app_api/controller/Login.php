<?php
/**
 * Created by PhpStorm.
 * User: Administrator
 * Date: 2020/3/26
 * Time: 18:37
 * Description:
 */
namespace app\app_api\controller;
use app\core\util\MiniProgramService;
use service\JsonService;
use service\UtilService;
use think\Cache;
use think\Controller;
use think\Request;
class Login{
    /**
     * 获取用户信息
     * @param Request $request
     * @return \think\response\Json
     */
    public function index(Request $request){
        $data = UtilService::postMore([
            ['code',''],
            ['cache_key',''],
        ],$request);//获取前台传的code
        if(!Cache::has('eb_api_code_'.$data['cache_key'])) return JsonService::status('410','获取会话密匙失败');
        $data['session_key']=Cache::get('eb_api_code_'.$data['cache_key']);

    }
    /**
     * 根据前台传code  获取 openid 和  session_key //会话密匙
     * @param string $code
     * @return array|mixed
     */
    public function setCode(Request $request){
        list($code) = UtilService::postMore([['code', '']], $request, true);//获取前台传的code
        if ($code == '') return JsonService::fail('');
        try{
            $userInfo = MiniProgramService::getUserInfo($code);
        }catch (\Exception $e){
            return JsonService::fail('获取session_key失败，请检查您的配置！',['line'=>$e->getLine(),'message'=>$e->getMessage()]);
        }
        $cache_key = md5(time().$code);
        if (isset($userInfo['session_key'])){
            Cache::set('eb_api_code_'.$cache_key, $userInfo['session_key'], 86400);
            return JsonService::successful(['cache_key'=>$cache_key]);
        }else
            return JsonService::fail('获取会话密匙失败');
    }


}