import type { Joke } from "@prisma/client";
import type { LoaderFunction } from "@remix-run/node";
import { Link, useLoaderData, useParams } from "@remix-run/react";

import { db } from "~/utils/db.server";

type LoaderData = { joke: Joke };
export const loader: LoaderFunction = async ({ params }) => {
  let joke = await db.joke.findUnique({
    where: { id: params.jokeId },
  });

  if (!joke) throw new Error("Joke not found");
  let data: LoaderData = { joke };
  return data;
};

export default function JokeRoute() {
  let data = useLoaderData<LoaderData>();
  return (
    <div>
      <p>Here's your hilarious joke:</p>
      <p>{data.joke.content}</p>
      <Link to=".">{data.joke.name} Permalink</Link>
    </div>
  );
}

export function ErrorBoundary() {
  const { jokeId } = useParams();
  return (
    <div className="error-container">{`There was an error loading joke by the id ${jokeId}. Sorry.`}</div>
  );
}
