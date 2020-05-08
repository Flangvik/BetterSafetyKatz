using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BetterSafetyKatz
{
    public class Helpers
    {
        //Ripped from StackOverFlow
        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        //https://stackoverflow.com/questions/15249138/pick-random-char
        public static char GetLetter()
        {
            string chars = "$%#@!*abcdefghijklmnopqrstuvwxyz1234567890?;:ABCDEFGHIJKLMNOPQRSTUVWXYZ^&";
            Random rand = new Random();
            int num = rand.Next(0, chars.Length - 1);
            return chars[num];
        }

        //https://stackoverflow.com/questions/5069687/find-character-with-most-occurrences-in-string
        public static char MostOccurringCharInString(string charString)
        {
            int mostOccurrence = -1;
            char mostOccurringChar = ' ';
            foreach (char currentChar in charString)
            {
                int foundCharOccreence = 0;
                foreach (char charToBeMatch in charString)
                {
                    if (currentChar == charToBeMatch)
                        foundCharOccreence++;
                }
                if (mostOccurrence < foundCharOccreence)
                {
                    mostOccurrence = foundCharOccreence;
                    mostOccurringChar = currentChar;
                }
            }
            return mostOccurringChar;
        }

    }
}
