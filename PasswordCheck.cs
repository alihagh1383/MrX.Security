using System.Text.RegularExpressions;

namespace MrX.Security
{
    public static class PasswordCheck
    {
        public static bool Letters_checker(string password)
        {
            if (string.IsNullOrEmpty(password) || !Regex.IsMatch(password, "[A-Za-z]")) return false;
            else return true;
        }
        public static bool Numbers_checker(string password)
        {
            if (string.IsNullOrEmpty(password) || !Regex.IsMatch(password, "[0-9]")) return false;
            else return true;

        }
        public static bool Special_Characters_checker(string password)
        {
            if (string.IsNullOrEmpty(password) || !Regex.IsMatch(password, "[!@#$%^&*()]")) return false;
            else return true;
            
        }
    }
}
