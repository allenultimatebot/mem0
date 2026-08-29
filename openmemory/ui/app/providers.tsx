"use client";

import { Provider } from "react-redux";
import { store } from "../store/store";
import axios from "axios";

const apiToken = process.env.NEXT_PUBLIC_OPENMEMORY_API_TOKEN;
if (apiToken) {
  axios.defaults.headers.common["X-OpenMemory-Token"] = apiToken;
}

export function Providers({ children }: { children: React.ReactNode }) {
  return <Provider store={store}>{children}</Provider>;
}
