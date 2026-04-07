import { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';
import type { PracticeScenario } from '../types';

interface AcademyContextValue {
  activeScenario: PracticeScenario | null;
  activeLessonId: string | null;
  launchScenario: (scenario: PracticeScenario) => void;
  setActiveLessonId: (lessonId: string | null) => void;
  clearScenario: () => void;
}

const AcademyContext = createContext<AcademyContextValue | undefined>(undefined);

export const AcademyProvider = ({ children }: { children: ReactNode }) => {
  const [activeScenario, setActiveScenario] = useState<PracticeScenario | null>(null);
  const [activeLessonId, setActiveLessonId] = useState<string | null>(null);

  const launchScenario = (scenario: PracticeScenario) => {
    setActiveScenario(scenario);
    setActiveLessonId(scenario.lessonId);
  };

  const clearScenario = () => {
    setActiveScenario(null);
  };

  return (
    <AcademyContext.Provider
      value={{
        activeScenario,
        activeLessonId,
        launchScenario,
        setActiveLessonId,
        clearScenario,
      }}
    >
      {children}
    </AcademyContext.Provider>
  );
};

export const useAcademy = () => {
  const context = useContext(AcademyContext);
  if (!context) {
    throw new Error('useAcademy must be used within an AcademyProvider.');
  }

  return context;
};
