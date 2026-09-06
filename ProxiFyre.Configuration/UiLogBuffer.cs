using System;
using System.Text;

namespace ProxiFyre.Configuration
{
    /// <summary>
    /// Bounded, line-aware UI log retention. Normal messages are trimmed only
    /// through complete lines. A single oversized message keeps its newest
    /// configured-size portion so UI memory remains bounded.
    /// </summary>
    public sealed class UiLogBuffer
    {
        public const int DefaultMaximumCharacters = 20000;
        private readonly int _maximumCharacters;
        private readonly StringBuilder _text = new StringBuilder();

        public UiLogBuffer(int maximumCharacters = DefaultMaximumCharacters)
        {
            if (maximumCharacters < 256)
                throw new ArgumentOutOfRangeException(nameof(maximumCharacters));
            _maximumCharacters = maximumCharacters;
        }

        public bool WasTrimmed { get; private set; }
        public string Text { get { return _text.ToString(); } }

        public void Append(string value)
        {
            var line = value ?? string.Empty;
            if (!line.EndsWith(Environment.NewLine, StringComparison.Ordinal))
                line += Environment.NewLine;

            if (line.Length > _maximumCharacters)
            {
                _text.Clear();
                _text.Append(line.Substring(line.Length - _maximumCharacters));
                WasTrimmed = true;
                return;
            }

            _text.Append(line);
            if (_text.Length <= _maximumCharacters)
                return;

            var removeCount = _text.Length - _maximumCharacters;
            var boundary = _text.ToString().IndexOf(
                Environment.NewLine, removeCount, StringComparison.Ordinal);
            if (boundary >= 0)
                removeCount = boundary + Environment.NewLine.Length;

            _text.Remove(0, Math.Min(removeCount, _text.Length));
            WasTrimmed = true;
        }
    }
}
