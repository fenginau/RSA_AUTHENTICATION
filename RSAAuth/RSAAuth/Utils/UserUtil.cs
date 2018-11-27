using System;
using System.Linq;
using NLog;
using RSAAuth.DBContext;
using RSAAuth.Models;

namespace RSAAuth.Utils
{
    public class UserUtil
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        internal static void CreateUser(UserModel user)
        {
            try
            {
                using (var context = new AuthContext())
                {
                    if (context.User.FirstOrDefault(u => u.Id == user.Id) != null)
                    {
                        context.User.Update(user);
                    }
                    else
                    {
                        context.User.Add(user);
                    }

                    try
                    {
                        RsaUtil.GenerateUserRsaKeyPair(user.Id);
                        context.SaveChanges();
                    }
                    catch (Exception e)
                    {
                        Logger.Error(e);
                    }

                }
            }
            catch (Exception e)
            {
                Logger.Error(e);
                throw new Exception("Error when creating the user.");
            }
        }

        internal static void GetUserIdByUserName(string userName)
        {

        }
    }
}
