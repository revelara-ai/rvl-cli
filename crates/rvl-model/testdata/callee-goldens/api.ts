import axios from "axios";

export const fetchUser = async (id: string): Promise<User> => {
  const res = await axios.get(`/users/${id}`, { timeout: 2000 });
  return res.data;
};

const retrying: Retry = (fn) => fn();

function* pages(start: number) {
  yield start;
}

export async function loadUser(id: string) {
  const user = await retrying(() => fetchUser(id));
  for (const p of pages(1)) {
    console.log(p);
  }
  return user;
}
