using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OwinExsample.Models
{
    public class UserService
    {
        public User GetUserByCredentials(string email,string password)
        {
            if (email != "email@domain.com" || password != "password")
                return null;

            User user = new User() { Id = "1", Email = "email@domain.com", Password = "password", Name = "Test" };
            if(user != null)
            {
                user.Password = string.Empty;
            }
            return user;
        }
    }
}