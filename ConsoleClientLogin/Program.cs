using System;
using System.Net;
using System.Collections.Specialized;
using System.Text;

namespace ConsoleClientLogin
{
    class Program
    {
        static void Main(string[] args)
        {
            string filePath = GetUserInfoFilePath();
            string userInfo = fileToString(filePath);
            if (userInfo == "")
            {
                Console.WriteLine("请登录！");
                Console.ReadKey();

                Console.WriteLine("请输入账号：");
                string userName = Console.ReadLine();
                Console.WriteLine("请输入密码：");
                string password = Console.ReadLine();

                using (var client = new WebClient())
                {
                    var values = new NameValueCollection();
                    values["client_id"] = "passwordclient";
                    values["client_secret"] = "secret";
                    values["grant_type"] = "password";
                    values["username"] = "bob";
                    values["password"] = "bob";
                    var response = client.UploadValues("http://localhost:5000/connect/token", values);
                    var responseString = Encoding.Default.GetString(response);

                    Console.WriteLine(responseString);
                    SavaProcess(filePath, responseString);
                }

            }
            else
            {
                Console.WriteLine("已经登陆过");
            }
        }

        /// <summary>
        /// 获取用户文件信息路径
        /// </summary>
        /// <returns></returns>
        public static string GetUserInfoFilePath()
        {
            string FileName = "userInfo.txt";
            //设置目录
            string CurDir = System.AppDomain.CurrentDomain.BaseDirectory + @"UserSaveDir";
            //判断路径是否存在
            if (!System.IO.Directory.Exists(CurDir))
            {
                System.IO.Directory.CreateDirectory(CurDir);
            }
            //不存在就创建
            string FilePath = CurDir + FileName;
            return FilePath;
        }

        /// <summary>
        /// 保存数据data到文件
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="data"></param>
        public static void SavaProcess(string filePath, string data)
        {
            //文件覆盖方式添加内容
            System.IO.StreamWriter file = new System.IO.StreamWriter(filePath, false);
            //保存数据到文件
            file.Write(data);
            //关闭文件
            file.Close();
            //释放对象
            file.Dispose();
        }

        /// <summary>
        /// 获取文件中的数据
        /// </summary>
        /// <param name="args"></param>
        public static string fileToString(String filePath)
        {
            string strData = "";
            try
            {
                string line;
                // 创建一个 StreamReader 的实例来读取文件 ,using 语句也能关闭 StreamReader
                using (System.IO.StreamReader sr = new System.IO.StreamReader(filePath))
                {
                    // 从文件读取并显示行，直到文件的末尾 
                    while ((line = sr.ReadLine()) != null)
                    {
                        //Console.WriteLine(line);
                        strData = line;
                    }
                }
            }
            catch (Exception e)
            {
                // 向用户显示出错消息
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }
            return strData;
        }
    }
}
