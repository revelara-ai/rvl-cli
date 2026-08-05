// C++ WITHOUT a compile db is a documented abstention class: template and
// include flags make a flagless parse guesswork, so this file must produce
// zero packets and be counted in the retrieval stats instead.
struct Curl {
  int perform();
};

int use(Curl &c) { return c.perform(); }
