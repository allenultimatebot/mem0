"use client";

import { Button } from "@/components/ui/button";
import { HiHome, HiMiniRectangleStack } from "react-icons/hi2";
import { RiApps2AddFill } from "react-icons/ri";
import { FiRefreshCcw } from "react-icons/fi";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { CreateMemoryDialog } from "@/app/memories/components/CreateMemoryDialog";
import { useMemoriesApi } from "@/hooks/useMemoriesApi";
import Image from "next/image";
import { useStats } from "@/hooks/useStats";
import { useAppsApi } from "@/hooks/useAppsApi";
import { Settings } from "lucide-react";
import { useConfig } from "@/hooks/useConfig";

export function Navbar() {
  const pathname = usePathname();

  const memoriesApi = useMemoriesApi();
  const appsApi = useAppsApi();
  const statsApi = useStats();
  const configApi = useConfig();

  // Define route matchers with typed parameter extraction
  const routeBasedFetchMapping: {
    match: RegExp;
    getFetchers: (params: Record<string, string>) => (() => Promise<any>)[];
  }[] = [
    {
      match: /^\/memory\/([^/]+)$/,
      getFetchers: ({ memory_id }) => [
        () => memoriesApi.fetchMemoryById(memory_id),
        () => memoriesApi.fetchAccessLogs(memory_id),
        () => memoriesApi.fetchRelatedMemories(memory_id),
      ],
    },
    {
      match: /^\/apps\/([^/]+)$/,
      getFetchers: ({ app_id }) => [
        () => appsApi.fetchAppMemories(app_id),
        () => appsApi.fetchAppAccessedMemories(app_id),
        () => appsApi.fetchAppDetails(app_id),
      ],
    },
    {
      match: /^\/memories$/,
      getFetchers: () => [memoriesApi.fetchMemories],
    },
    {
      match: /^\/apps$/,
      getFetchers: () => [appsApi.fetchApps],
    },
    {
      match: /^\/$/,
      getFetchers: () => [statsApi.fetchStats, memoriesApi.fetchMemories],
    },
    {
      match: /^\/settings$/,
      getFetchers: () => [configApi.fetchConfig],
    },
  ];

  const getFetchersForPath = (path: string) => {
    for (const route of routeBasedFetchMapping) {
      const match = path.match(route.match);
      if (match) {
        if (route.match.source.includes("memory")) {
          return route.getFetchers({ memory_id: match[1] });
        }
        if (route.match.source.includes("app")) {
          return route.getFetchers({ app_id: match[1] });
        }
        return route.getFetchers({});
      }
    }
    return [];
  };

  const handleRefresh = async () => {
    const fetchers = getFetchersForPath(pathname);
    await Promise.allSettled(fetchers.map((fn) => fn()));
  };

  const isActive = (href: string) => {
    if (href === "/") return pathname === href;
    return pathname.startsWith(href.substring(0, 5));
  };

  const activeClass = "bg-zinc-800 text-white border-zinc-600";
  const inactiveClass = "text-zinc-300";

  return (
    <header className="sticky top-0 z-50 w-full border-b border-zinc-800 bg-zinc-950/95 backdrop-blur supports-[backdrop-filter]:bg-zinc-950/60">
      <div className="container flex min-w-0 flex-wrap items-center justify-between gap-y-2 py-2 lg:h-14 lg:flex-nowrap lg:py-0">
        <Link href="/" className="flex min-w-0 items-center gap-2">
          <Image src="/logo.svg" alt="OpenMemory" width={26} height={26} />
          <span className="truncate text-xl font-medium">OpenMemory</span>
        </Link>
        <div className="order-1 flex shrink-0 items-center gap-2 lg:order-3 lg:gap-4">
          <Button
            onClick={handleRefresh}
            variant="outline"
            size="sm"
            aria-label="Refresh"
            title="Refresh"
            className="border-zinc-700/50 bg-zinc-900 px-2 hover:bg-zinc-800 lg:px-3"
          >
            <FiRefreshCcw className="transition-transform duration-300 group-hover:rotate-180" />
            <span className="hidden lg:inline">Refresh</span>
          </Button>
          <CreateMemoryDialog />
        </div>
        <nav aria-label="Primary navigation" className="order-2 flex w-full items-center justify-between gap-1 lg:w-auto lg:gap-2">
          <Link href="/" aria-label="Dashboard" title="Dashboard" className="flex-1 lg:flex-none">
            <Button
              asChild
              variant="outline"
              size="sm"
              className={`flex w-full items-center justify-center gap-2 border-none px-2 lg:w-auto lg:px-3 ${
                isActive("/") ? activeClass : inactiveClass
              }`}
            >
              <span>
                <HiHome />
                <span className="hidden lg:inline">Dashboard</span>
              </span>
            </Button>
          </Link>
          <Link href="/memories" aria-label="Memories" title="Memories" className="flex-1 lg:flex-none">
            <Button
              asChild
              variant="outline"
              size="sm"
              className={`flex w-full items-center justify-center gap-2 border-none px-2 lg:w-auto lg:px-3 ${
                isActive("/memories") ? activeClass : inactiveClass
              }`}
            >
              <span>
                <HiMiniRectangleStack />
                <span className="hidden lg:inline">Memories</span>
              </span>
            </Button>
          </Link>
          <Link href="/apps" aria-label="Apps" title="Apps" className="flex-1 lg:flex-none">
            <Button
              asChild
              variant="outline"
              size="sm"
              className={`flex w-full items-center justify-center gap-2 border-none px-2 lg:w-auto lg:px-3 ${
                isActive("/apps") ? activeClass : inactiveClass
              }`}
            >
              <span>
                <RiApps2AddFill />
                <span className="hidden lg:inline">Apps</span>
              </span>
            </Button>
          </Link>
          <Link href="/settings" aria-label="Settings" title="Settings" className="flex-1 lg:flex-none">
            <Button
              asChild
              variant="outline"
              size="sm"
              className={`flex w-full items-center justify-center gap-2 border-none px-2 lg:w-auto lg:px-3 ${
                isActive("/settings") ? activeClass : inactiveClass
              }`}
            >
              <span>
                <Settings />
                <span className="hidden lg:inline">Settings</span>
              </span>
            </Button>
          </Link>
        </nav>
      </div>
    </header>
  );
}
