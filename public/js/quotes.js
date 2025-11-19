// public/js/quotes.js
// 96 QUOTES ÉPICAS – TODAS AS QUE ENVIASTE + FUNCIONAMENTO PERFEITO

const quotes = [
  { text: "The only thing we have to fear is fear itself.", author: "Franklin D. Roosevelt" },
  { text: "That which does not kill us makes us stronger.", author: "Friedrich Nietzsche" },
  { text: "I think, therefore I am.", author: "René Descartes" },
  { text: "The unexamined life is not worth living.", author: "Socrates" },
  { text: "To be, or not to be, that is the question.", author: "William Shakespeare" },
  { text: "Imagination is more important than knowledge.", author: "Albert Einstein" },
  { text: "Injustice anywhere is a threat to justice everywhere.", author: "Martin Luther King Jr." },
  { text: "The greatest glory in living lies not in never falling, but in rising every time we fall.", author: "Nelson Mandela" },
  { text: "If you judge people, you have no time to love them.", author: "Mother Teresa" },
  { text: "The way to get started is to quit talking and begin doing.", author: "Walt Disney" },
  { text: "Stay hungry. Stay foolish.", author: "Steve Jobs" },
  { text: "The purpose of our lives is to be happy.", author: "Dalai Lama" },
  { text: "Do one thing every day that scares you.", author: "Eleanor Roosevelt" },
  { text: "Life is what happens when you're busy making other plans.", author: "John Lennon" },
  { text: "Be the change you wish to see in the world.", author: "Mahatma Gandhi" },
  { text: "It always seems impossible until it's done.", author: "Nelson Mandela" },
  { text: "Success is not final, failure is not fatal: it is the courage to continue that counts.", author: "Winston Churchill" },
  { text: "The best way to predict the future is to invent it.", author: "Alan Kay" },
  { text: "You miss 100% of the shots you don't take.", author: "Wayne Gretzky" },
  { text: "The mind is everything. What you think you become.", author: "Buddha" },
  { text: "Dream big and dare to fail.", author: "Norman Vaughan" },
  { text: "A goal without a plan is just a wish.", author: "Antoine de Saint-Exupéry" },
  { text: "The best time to plant a tree was 20 years ago. The second best time is now.", author: "Chinese proverb" },
  { text: "The only way to do great work is to love what you do.", author: "Steve Jobs" },
  { text: "It does not matter how slowly you go as long as you do not stop.", author: "Confucius" },
  { text: "Quality is not an act, it is a habit.", author: "Aristotle" },
  { text: "Don't count the days, make the days count.", author: "Muhammad Ali" },
  { text: "Nothing will work unless you do.", author: "Maya Angelou" },
  { text: "Action is the foundational key to all success.", author: "Pablo Picasso" },
  { text: "Turn your wounds into wisdom.", author: "Oprah Winfrey" },
  { text: "Life is either a daring adventure or nothing at all.", author: "Helen Keller" },
  { text: "Be yourself; everyone else is already taken.", author: "Oscar Wilde" },
  { text: "A friend is someone who knows all about you and still loves you.", author: "Elbert Hubbard" },
  { text: "Whoever is happy will make others happy too.", author: "Anne Frank" },
  { text: "Do not go where the path may lead, go instead where there is no path and leave a trail.", author: "Ralph Waldo Emerson" },
  { text: "The only impossible journey is the one you never begin.", author: "Tony Robbins" },
  { text: "An eye for an eye only ends up making the whole world blind.", author: "Mahatma Gandhi" },
  { text: "You become what you believe.", author: "Oprah Winfrey" },
  { text: "We can do no great things; only small things with great love.", author: "Mother Teresa" },
  { text: "He who has a why to live can bear almost any how.", author: "Friedrich Nietzsche" },
  { text: "The greatest wealth is to live content with little.", author: "Plato" },
  { text: "Be kind, for everyone you meet is fighting a hard battle.", author: "Plato" },
  { text: "If opportunity doesn't knock, build a door.", author: "Milton Berle" },
  { text: "Everything you can imagine is real.", author: "Pablo Picasso" },
  { text: "Courage is grace under pressure.", author: "Ernest Hemingway" },
  { text: "It is never too late to be what you might have been.", author: "George Eliot" },
  { text: "Not everything that is faced can be changed, but nothing can be changed until it is faced.", author: "James Baldwin" },
  { text: "To love and be loved is to feel the sun from both sides.", author: "David Viscott" },
  { text: "Knowing yourself is the beginning of all wisdom.", author: "Aristotle" },
  { text: "Happiness depends upon ourselves.", author: "Aristotle" },
  { text: "If you can't explain it simply, you don't understand it well enough.", author: "Albert Einstein" },
  { text: "We are what we repeatedly do. Excellence, then, is not an act but a habit.", author: "Aristotle" },
  { text: "A room without books is like a body without a soul.", author: "Cicero" },
  { text: "The future belongs to those who believe in the beauty of their dreams.", author: "Eleanor Roosevelt" },
  { text: "Life is really simple, but we insist on making it complicated.", author: "Confucius" },
  { text: "Get busy living or get busy dying.", author: "Stephen King" },
  { text: "The best revenge is massive success.", author: "Frank Sinatra" },
  { text: "If you want something you've never had, you must be willing to do something you've never done.", author: "Thomas Jefferson" },
  { text: "The higher we soar, the smaller we appear to those who cannot fly.", author: "Friedrich Nietzsche" },
  { text: "Peace begins with a smile.", author: "Mother Teresa" },
  { text: "Education is the most powerful weapon which you can use to change the world.", author: "Nelson Mandela" },
  { text: "Try not to become a man of success, but rather try to become a man of value.", author: "Albert Einstein" },
  { text: "The measure of who we are is what we do with what we have.", author: "Vince Lombardi" },
  { text: "Everything has beauty, but not everyone sees it.", author: "Confucius" },
  { text: "If you tell the truth, you don't have to remember anything.", author: "Mark Twain" },
  { text: "The best way out is always through.", author: "Robert Frost" },
  { text: "To succeed in life, you need two things: ignorance and confidence.", author: "Mark Twain" },
  { text: "We don't see things as they are, we see them as we are.", author: "Anaïs Nin" },
  { text: "Change your thoughts and you change your world.", author: "Norman Vincent Peale" },
  { text: "What we think, we become.", author: "Buddha" },
  { text: "You only live once, but if you do it right, once is enough.", author: "Mae West" },
  { text: "A wise man changes his mind, a fool never will.", author: "Spanish Proverb" },
  { text: "Silence is a source of great strength.", author: "Lao Tzu" },
  { text: "Simplicity is the ultimate sophistication.", author: "Leonardo da Vinci" },
  { text: "We make a living by what we get, but we make a life by what we give.", author: "Winston Churchill" },
  { text: "Act as if what you do makes a difference. It does.", author: "William James" },
  { text: "Patience is bitter, but its fruit is sweet.", author: "Aristotle" },
  { text: "Well done is better than well said.", author: "Benjamin Franklin" },
  { text: "Gratitude turns what we have into enough.", author: "Aesop" },
  { text: "Hope is being able to see that there is light despite all of the darkness.", author: "Desmond Tutu" },
  { text: "Kindness is the language which the deaf can hear and the blind can see.", author: "Mark Twain" },
  { text: "A man is but what he believes.", author: "Mahatma Gandhi" },
  { text: "Love all, trust a few, do wrong to none.", author: "William Shakespeare" },
  { text: "We must not allow other people’s limited perceptions to define us.", author: "Virginia Satir" },
  { text: "The harder you work, the luckier you get.", author: "Gary Player" },
  { text: "Everything negative – pressure, challenges – is an opportunity to rise.", author: "Kobe Bryant" },
  { text: "The biggest risk is not taking any risk.", author: "Mark Zuckerberg" },
  { text: "You can’t use up creativity. The more you use, the more you have.", author: "Maya Angelou" },
  { text: "Don’t watch the clock; do what it does. Keep going.", author: "Sam Levenson" },
  { text: "Strive not to be a success, but rather to be of value.", author: "Albert Einstein" },
  { text: "When you have a dream, you’ve got to grab it and never let go.", author: "Carol Burnett" },
  { text: "Hardships often prepare ordinary people for an extraordinary destiny.", author: "C.S. Lewis" },
  { text: "The secret of getting ahead is getting started.", author: "Mark Twain" },
  { text: "Whatever you are, be a good one.", author: "Abraham Lincoln" },
  { text: "There is nothing impossible to him who will try.", author: "Alexander the Great" },
  { text: "Logic will get you from A to B. Imagination will take you everywhere.", author: "Albert Einstein" },
  { text: "When you arise in the morning, think of what a privilege it is to be alive.", author: "Marcus Aurelius" },
  { text: "We become what we think about.", author: "Earl Nightingale" },
  { text: "If you want to lift yourself up, lift up someone else.", author: "Booker T. Washington" },
  { text: "You are never too old to set another goal or to dream a new dream.", author: "C.S. Lewis" },
  { text: "Success is how high you bounce when you hit bottom.", author: "George S. Patton" },
  { text: "Doubt kills more dreams than failure ever will.", author: "Suzy Kassem" }
];

// FUNÇÃO PRINCIPAL – USADA NO statistics.ejs
function getRandomQuote() {
  const q = quotes[Math.floor(Math.random() * quotes.length)];
  return { text: q.text, author: q.author };
}

// FUNÇÃO ANTIGA (para compatibilidade total)
function showRandomQuote() {
  const q = getRandomQuote();
  const textEl = document.getElementById("quote-text") || document.getElementById("quote");
  const authorEl = document.getElementById("quote-author") || document.getElementById("author");
  
  if (textEl) textEl.textContent = q.text;
  if (authorEl) authorEl.textContent = "— " + q.author;
}

// EXECUTA AO CARREGAR A PÁGINA
document.addEventListener("DOMContentLoaded", () => {
  showRandomQuote();
});