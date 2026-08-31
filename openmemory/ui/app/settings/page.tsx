"use client";

import { useState, useEffect } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { SaveIcon, RotateCcw } from "lucide-react"
import { FormView } from "@/components/form-view"
import { JsonEditor } from "@/components/json-editor"
import { useConfig } from "@/hooks/useConfig"
import { useSelector } from "react-redux"
import { RootState } from "@/store/store"
import { useToast } from "@/components/ui/use-toast"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"

export default function SettingsPage() {
  const { toast } = useToast()
  const configState = useSelector((state: RootState) => state.config)
  const [settings, setSettings] = useState({
    openmemory: configState.openmemory || {
      custom_instructions: null
    },
    mem0: configState.mem0
  })
  const [viewMode, setViewMode] = useState<"form" | "json">("form")
  const { fetchConfig, saveConfig, resetConfig, isLoading, error } = useConfig()

  useEffect(() => {
    // Load config from API on component mount
    const loadConfig = async () => {
      try {
        await fetchConfig()
      } catch (error) {
        toast({
          title: "Error",
          description: "Failed to load configuration",
          variant: "destructive",
        })
      }
    }
    
    loadConfig()
  }, [])

  // Update local state when redux state changes
  useEffect(() => {
    setSettings(prev => ({
      ...prev,
      openmemory: configState.openmemory || { custom_instructions: null },
      mem0: configState.mem0
    }))
  }, [configState.openmemory, configState.mem0])

  const handleSave = async () => {
    try {
      await saveConfig({ 
        openmemory: settings.openmemory,
        mem0: settings.mem0 
      })
      toast({
        title: "Settings saved",
        description: "Your configuration has been updated successfully.",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to save configuration",
        variant: "destructive",
      })
    }
  }

  const handleReset = async () => {
    try {
      await resetConfig()
      toast({
        title: "Settings reset",
        description: "Configuration has been reset to default values.",
      })
      await fetchConfig()
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to reset configuration",
        variant: "destructive",
      })
    }
  }

  return (
    <div className="min-w-0 py-6 text-white">
      <div className="container mx-auto min-w-0 max-w-4xl py-10">
        <div className="mb-8 flex min-w-0 flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0 animate-fade-slide-down">
            <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
            <p className="text-muted-foreground mt-1">Manage your OpenMemory and Mem0 configuration</p>
          </div>
          <div className="flex w-full flex-wrap gap-2 sm:w-auto">
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" className="flex-1 border-zinc-800 text-zinc-200 hover:bg-zinc-700 hover:text-zinc-50 animate-fade-slide-down sm:flex-none" disabled={isLoading}>
                  <RotateCcw className="mr-2 h-4 w-4" />
                  Reset Defaults
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Reset Configuration?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will reset all settings to the system defaults. Any custom configuration will be lost.
                    API keys will be set to use environment variables.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleReset} className="bg-red-600 hover:bg-red-700">
                    Reset
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
            
            <Button onClick={handleSave} className="flex-1 bg-primary hover:bg-primary/90 animate-fade-slide-down sm:flex-none" disabled={isLoading}>
              <SaveIcon className="mr-2 h-4 w-4" />
              {isLoading ? "Saving..." : "Save Configuration"}
            </Button>
          </div>
        </div>

        <Tabs value={viewMode} onValueChange={(value) => setViewMode(value as "form" | "json")} className="min-w-0 w-full animate-fade-slide-down delay-1">
          <TabsList className="grid w-full grid-cols-2 mb-8">
            <TabsTrigger value="form">Form View</TabsTrigger>
            <TabsTrigger value="json">JSON Editor</TabsTrigger>
          </TabsList>

          <TabsContent value="form">
            <FormView settings={settings} onChange={setSettings} />
          </TabsContent>

          <TabsContent value="json">
            <Card>
              <CardHeader>
                <CardTitle>JSON Configuration</CardTitle>
                <CardDescription>Edit the entire configuration directly as JSON</CardDescription>
              </CardHeader>
              <CardContent>
                <JsonEditor value={settings} onChange={setSettings} />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
