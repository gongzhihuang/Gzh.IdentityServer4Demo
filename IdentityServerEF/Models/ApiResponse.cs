namespace IdentityServerEF.Models
{
    public class ApiResponse
    {
        /// <summary>
        /// 操作消息【当Status不为 200时，显示详细的错误信息】
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// 操作状态码，200为正常
        /// </summary>
        public int Code { get; set; }

        public ApiResponse()
        {
            Code = 200;
            Message = "操作成功";
        }
    }


    /// <summary>
    /// WEBAPI通用返回泛型基类
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class ApiResponse<T> : ApiResponse
    {
        /// <summary>
        /// 回传的结果
        /// </summary>
        public T Result { get; set; }
    }
}