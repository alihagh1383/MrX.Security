using System.Text.RegularExpressions;

namespace MrX.Security
{
    public static class PasswordCheck
    {
        public static bool Letters_checker(string Password)
        {
            if (string.IsNullOrEmpty(Password) || !Regex.IsMatch(Password, "[A-Za-z]")) return false;
            else return true;
        }
        public static bool Numbers_checker(string Password)
        {
            if (string.IsNullOrEmpty(Password) || !Regex.IsMatch(Password, "[0-9]")) return false;
            else return true;

        }
        public static bool Special_Characters_checker(string Password)
        {
            if (string.IsNullOrEmpty(Password) || !Regex.IsMatch(Password, "[!@#$%^&*()]")) return false;
            else return true;
            
        }
    }
}
