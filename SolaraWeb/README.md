# SolaraWeb - Advanced ESP Menu System

A comprehensive web-based ESP (Extra Sensory Perception) menu system with real-time configuration, auto-save functionality, and advanced visual enhancements. Built with modern web technologies and featuring a sophisticated settings management system.

## 🏗️ Project Structure

```
SolaraWeb/
├── index.html              # Main loader interface
├── Main Page/              # Product interface  
│   ├── index.html         # Download/activation page
│   └── _app/              # SvelteKit build artifacts
├── Menu/                  # Complete ESP configuration system
│   ├── index.html         # Advanced ESP menu (2.9K+ lines)
│   ├── _app/              # SvelteKit build artifacts
│   └── menu/              # Menu subsystem
│       └── index.html     # Additional menu interface
└── README.md              # This documentation
```

## 🚀 Key Features

### 💾 Auto-Save System
- **Real-time persistence** - All settings save automatically on change
- **Cross-session memory** - Configuration persists across browser restarts
- **Master-child dependencies** - Smart restoration of toggle hierarchies
- **Color synchronization** - Duplicate elements stay synchronized
- **Version control** - Configuration versioning with timestamp tracking

### 🎨 Advanced UI/UX
- **Dynamic theming** - Dark mode with CSS custom properties
- **Responsive design** - Optimized for all screen sizes
- **Custom animations** - Smooth transitions and state changes
- **Collapsible sections** - Organized feature grouping
- **Toast notifications** - Real-time user feedback
- **Tab system** - Multi-panel navigation (Visuals/Performance)

### 🛡️ Architecture
- **Modular JavaScript** - Object-oriented MenuApp class
- **Event delegation** - Efficient DOM event handling
- **Error recovery** - Graceful handling of corrupted configurations
- **Debug system** - Comprehensive debugging tools for development
- **Performance optimized** - Efficient DOM manipulation and state management

---

## 📋 ESP FEATURES

### 🎯 VISUALS TAB

#### Player ESP (Master Control)
**Master Toggle Behavior:**
- Controls all player-related visual features
- **Disable**: Instantly turns off all child features and makes them unclickable
- **Enable**: Restores previously enabled child features with state memory
- **Auto-enable**: Clicking disabled child features automatically enables master

**Player ESP Features:**
- 🦴 **Skeleton ESP** - Real-time bone structure visualization
  - Color customization with advanced color picker
  - Toggle-based enable/disable
- 📦 **Box ESP** - Player bounding boxes
  - 2D/3D rendering options
  - Customizable colors and transparency
- 👻 **Chams** - See-through player highlighting
  - Wall-hack style visibility
  - Custom color schemes
- ❤️ **Health ESP** - Dynamic health indicators
  - Real-time health bar display
  - Color-coded health levels
- 🏷️ **Name/Operator ESP** - Player identification
  - Display usernames and operator types
  - Distance-based scaling
- 📏 **Distance ESP** - Range indicators
  - Metric/imperial unit support
  - Distance-based visibility filtering
- 👁️ **Visibility Check** - Line-of-sight validation
  - Only shows ESP for visible targets
  - Performance optimization feature

#### Gadget ESP (Master Control)
**Smart Master Control:**
- Manages all gadget-related visual features
- **Child auto-enablement** - Clicking disabled children auto-enables master
- **Container management** - Disables pointer events when master is off

**Gadget ESP Features:**
- 🪤 **Trap ESP** - Surveillance device detection
  - Color-coded trap indicators
  - Range-based visibility
- 📹 **Camera ESP** - Security camera locations
  - Camera angle indicators
  - Status-based color coding
- 🛸 **Drone ESP** - Airborne device tracking
  - Real-time position updates
  - Flight path prediction
- 💥 **Destructibles ESP** - Breakable environment elements
  - Structural weak points
  - Damage state indicators
- 🚪 **Breaching ESP** - Entry point identification
  - Reinforcement status
  - Breach difficulty indicators
- 🔧 **Icons** - Gadget icon overlay system
  - Vector-based gadget icons
  - Replaces box indicators
- 🏷️ **Names** - Gadget name display
  - Text overlay system
  - Gadget type identification

#### Environment ESP (Master Control)
**Environmental Awareness:**
- 🎯 **Objectives ESP** - Mission-critical location markers
  - Bomb sites, hostage locations
  - Dynamic objective tracking
- ⏱️ **Bomb Timer** - Explosive countdown display
  - Time-to-detonation indicators
  - Defusal progress tracking

#### Custom ESP Elements
**Individual Features:**
- 🏥 **Health Bar** - Standalone health indicators
  - Position customization
  - Style selection options
- 📦 **Bounding Box** - Standalone box ESP
  - Independent of main box ESP
  - Custom styling options
- 🎯 **Head Circle** - Head-specific targeting
  - Precision aiming assistance
  - Adjustable radius
- 🦴 **Skeleton Alt** - Alternative skeleton rendering
  - Different bone visualization style
  - Independent color control

### ⚡ PERFORMANCE TAB

#### ESP Performance Controls
- 🖼️ **ESP FPS Limiter** - Frame rate optimization
  - Adjustable FPS cap (1-144 FPS)
  - Reduces system load during intensive ESP rendering
- 📏 **Distance Limiter** - Rendering distance control
  - Configurable maximum ESP distance
  - Performance scaling based on range
- 💾 **Auto-Save Interval** - Configuration persistence timing
  - Adjustable save frequency
  - Prevents data loss during crashes

#### Performance Monitoring
- 📊 **Real-time FPS Display** - Current frame rate monitoring
- 🎯 **ESP Object Count** - Active ESP element tracking
- 📈 **Performance Statistics** - System resource usage

---

## 🛠️ TECHNICAL IMPLEMENTATION

### MenuApp Class Architecture
```javascript
class MenuApp {
    constructor() {
        this.currentTab = 'visuals';           // Active tab state
        this.settings = {};                    // Feature settings object
        this.collapsedSections = {};           // UI state tracking
        this.autoSaveEnabled = true;           // Auto-save control flag
        this.loadingComplete = false;          // Initialization state
    }
    
    // Core initialization and event binding
    init()
    bindEvents()
    
    // Settings persistence
    saveSettings()                             // Real-time auto-save
    loadSettings()                             // Configuration restoration
    
    // UI state management
    switchTab(tabName)
    toggleSwitch(toggleElement)
    
    // Master-child toggle logic
    initMasterToggles()
    restoreToggles(togglesData)
    
    // Color management
    initColorPickers()
    createCustomColorPicker()
    
    // Performance optimization
    initPerformanceFeatures()
    startPerformanceMonitoring()
}
```

### Auto-Save System Details

#### Configuration Structure
```javascript
{
    version: '1.0',                           // Configuration version
    timestamp: 1642886400000,                 // Save timestamp
    currentTab: 'visuals',                    // Active tab
    collapsedSections: {                      // UI state
        'player-esp': false,
        'gadget-esp': true
    },
    ui: {
        toggles: {                            // All toggle states
            'icons-toggle': {
                state: true,                  // On/off state
                isMaster: false,              // Master toggle flag
                isChild: true,                // Child toggle flag
                group: 'gadget-esp',          // Parent group
                feature: 'icons',             // Feature identifier
                id: 'icons-toggle',           // DOM element ID
                index: 16,                    // DOM position
                labelText: 'Icons'            // Display text
            }
        },
        colors: {                             // Color configurations
            'skeleton': '#3b82f6',            // Hex color values
            'traps': '#ef4444',
            'cameras': '#10b981'
        },
        sliders: {                            // Slider values
            'espFpsSlider': 60,               // FPS limit setting
            'distanceSlider': 100             // Distance limit
        },
        selects: {                            // Dropdown selections
            'qualitySelect': 'high'           // Quality settings
        }
    }
}
```

#### Save/Load Process Flow
1. **Initialization Phase**
   - DOM attribute setup (`updateGadgetToggles()`, `updateEnvironmentToggles()`)
   - Event binding and master toggle initialization
   - Configuration loading with validation

2. **Real-time Save Process**
   - Triggered by any user interaction
   - Comprehensive DOM state scanning
   - Master-child relationship detection
   - Atomic localStorage write operation

3. **Restoration Process**
   - Multi-pass toggle restoration (Master → Child → Regular)
   - Color synchronization across duplicate elements
   - UI state reconstruction (opacity, pointer events)
   - Master auto-enablement for orphaned children

### Color System Implementation

#### Advanced Color Picker
- **HSV color space** - Hue, Saturation, Value manipulation
- **Real-time preview** - Instant color visualization
- **Hex/RGB input** - Multiple input formats
- **Color wheel interface** - Intuitive color selection
- **Synchronized updates** - Multiple elements with same feature sync automatically

#### Color Management Flow
```javascript
// Color picker creation and event handling
createCustomColorPicker(container, currentColor)
initColorWheelEvents(picker, container)

// Color conversion utilities
hexToRgb(hex) → {r, g, b}
rgbToHex(r, g, b) → "#rrggbb"
hexToHsv(hex) → {h, s, v}
hsvToHex(h, s, v) → "#rrggbb"

// Synchronized color application
// Updates ALL elements with matching data-feature
const allCircles = document.querySelectorAll(`[data-feature="${feature}"].color-circle`);
allCircles.forEach(circle => {
    circle.style.backgroundColor = finalColor;
    circle.setAttribute('data-color', finalColor);
});
```

### Master-Child Toggle System

#### Hierarchy Management
```javascript
// Master toggle controls child container
if (newState === 'checked') {
    childrenContainer.style.opacity = '1';
    childrenContainer.style.pointerEvents = 'auto';
} else {
    childrenContainer.style.opacity = '0.5';
    childrenContainer.style.pointerEvents = 'none';
    // Disable all child toggles
    childrenContainer.querySelectorAll('.child-toggle').forEach(child => {
        this.setToggleState(child, 'unchecked');
    });
}
```

#### Smart Child Interaction
```javascript
// Auto-enable master when child is clicked while disabled
if (container && container.style.pointerEvents === 'none' && masterToggle) {
    // Auto-enable the master toggle first
    this.setToggleState(masterToggle, 'checked');
    container.style.opacity = '1';
    container.style.pointerEvents = 'auto';
    
    // Show notification about auto-enabling master
    this.showToast(`${masterName} auto-enabled`, 'info');
}
```

### Error Handling & Recovery

#### Configuration Validation
```javascript
try {
    const savedConfig = localStorage.getItem('solaraEspConfig');
    if (savedConfig) {
        const config = JSON.parse(savedConfig);
        // Validate configuration structure
        // Apply with error recovery
    }
} catch (error) {
    console.log('Error loading configuration, starting fresh:', error);
    localStorage.removeItem('solaraEspConfig');
}
```

#### Debug System
```javascript
window.debugESP = {
    testSave: () => this.saveSettings(),
    testLoad: () => this.loadSettings(),
    clearStorage: () => localStorage.removeItem('solaraEspConfig'),
    showConfig: () => console.log(JSON.parse(localStorage.getItem('solaraEspConfig') || '{}')),
    testProblematicFeatures: () => { /* Comprehensive testing */ }
};
```

---

## 🎨 STYLING SYSTEM

### CSS Architecture
- **Custom Properties** - Dynamic theming with CSS variables
- **Component-based** - Modular styling approach
- **Responsive Design** - Mobile-first responsive layout
- **Animation System** - Smooth transitions and micro-interactions

### Theme System
```css
:root {
    --background: 222.2 84% 4.9%;           /* Dark background */
    --foreground: 210 40% 98%;              /* Light text */
    --primary: 210 40% 98%;                 /* Primary accent */
    --primary-foreground: 222.2 84% 4.9%;   /* Primary text */
    --muted: 217.2 32.6% 17.5%;             /* Muted elements */
    --border: 217.2 32.6% 17.5%;            /* Border colors */
    --ring: 212.7 26.8% 83.9%;             /* Focus rings */
}

.toggle-switch[data-state="checked"] {
    background-color: hsl(var(--primary));
}
```

### Component Styling
- **Toggle Switches** - Custom-styled toggle components with smooth animations
- **Color Pickers** - Advanced HSV color wheel with real-time preview
- **Sliders** - Custom range sliders with precise control
- **Notifications** - Toast notification system with slide animations
- **Tabs** - Dynamic tab system with slider indicator

---

## 📱 RESPONSIVE DESIGN

### Breakpoint System
- **Mobile**: 320px - 768px (Stacked layout, touch-optimized)
- **Tablet**: 768px - 1024px (Hybrid layout, mixed interactions)
- **Desktop**: 1024px+ (Full layout, mouse-optimized)

### Touch Optimization
- **Touch Targets** - Minimum 44px touch areas
- **Gesture Support** - Swipe navigation for mobile
- **Keyboard Navigation** - Full keyboard accessibility
- **Screen Readers** - ARIA labels and semantic HTML

---

## 🔧 DEVELOPMENT & DEBUGGING

### Debug Commands
Access debugging tools via browser console:
```javascript
// Test auto-save functionality
window.debugESP.testSave()

// Test configuration loading
window.debugESP.testLoad()

// Clear saved configuration
window.debugESP.clearStorage()

// Display current configuration
window.debugESP.showConfig()

// Test problematic features
window.debugESP.testProblematicFeatures()

// Step-by-step testing
window.debugESP.testIconsNamesStepByStep()
```

### Performance Monitoring
```javascript
// Monitor ESP performance
window.debugESP.monitorPerformance()

// Track memory usage
window.debugESP.checkMemoryUsage()

// Analyze DOM manipulation performance
window.debugESP.profileDOMOperations()
```

---

## 🚀 DEPLOYMENT

### Production Checklist
- ✅ Minify JavaScript and CSS
- ✅ Optimize image assets
- ✅ Enable gzip compression
- ✅ Configure cache headers
- ✅ Test cross-browser compatibility
- ✅ Validate accessibility compliance
- ✅ Performance audit with Lighthouse

### Browser Support
- **Chrome/Chromium**: 88+ ✅
- **Firefox**: 85+ ✅
- **Safari**: 14+ ✅
- **Edge**: 88+ ✅

### Performance Targets
- **First Contentful Paint**: < 1.5s
- **Largest Contentful Paint**: < 2.5s
- **Cumulative Layout Shift**: < 0.1
- **First Input Delay**: < 100ms

---

## 📄 LICENSE & CREDITS

**SolaraWeb ESP Menu System**
- Advanced ESP configuration interface
- Real-time auto-save functionality
- Comprehensive visual enhancement controls
- Professional-grade user experience

*Built with modern web technologies for optimal performance and user experience.*
- **Spectator List** - List of players currently spectating
- **Ignore Team** - Filters out teammates from ESP drawing

### Gadget ESP (Own Dropdown)
**Sub-feature Toggles:**
- **Trap ESP** - Kapkan traps, Lesion mines, Aruni gates, etc.
- **Camera ESP** - Default cameras, bulletproof cameras, Valkyrie cameras
- **Drone ESP** - Standard drones + Twitch drones
- **Hatch / Destructible ESP** - Breakable walls, hatches, barricades
- **Breaching Charge ESP** - Fuze clusters, thermite charges, exothermic charges
- **Icons** - Draw gadget icons instead of default boxes
- **Names** - Overlay textual gadget names on ESP elements

### Environment (Own Dropdown)
- **Objective ESP** - Bomb sites, hostage locations, secure area zone markers
- **Bomb Timer** - Show plant/defuse countdown overlay with progress indicators

### Visual Implementation Details
- **Color Picker System**: Custom-built color wheel with HSL/RGB controls
- **Real-time Preview**: Live color updates with smooth transitions
- **Risk Assessment**: Features labeled with risk levels (High Risk, Risky, Safe)
- **State Memory**: All visual preferences persist through localStorage

---

## 2. ⚡ PERFORMANCE

### FPS Management
- **FPS Meter** - Real-time frame rate display
- **ESP Overlay FPS** - Configurable range from 30-144 FPS
  - Slider control with real-time adjustment
  - Performance optimization based on selected FPS target
  - Automatic frame limiting to prevent system overload

### Distance Optimization  
- **ESP Distance Range** - Configurable visibility distance (10-100 meters)
  - Reduces rendering load by culling distant objects
  - Dynamic LOD (Level of Detail) based on distance
  - Performance scaling for different hardware capabilities

### Performance Optimizations
- **RequestAnimationFrame**: Smooth animations without blocking UI
- **Cached DOM Measurements**: Prevents layout thrashing
- **Debounced Input Handling**: Reduces unnecessary computations
- **Memory Management**: Proper cleanup methods to prevent memory leaks
- **Asset Optimization**: Immutable build artifacts with efficient caching

---

## 3. ⚙️ CONFIG

### Configuration Management System

#### Config Dropdown List
- **Saved Configurations**: Shows every saved configuration as a selectable entry
- **Profile Management**: Each entry includes a delete (trash-can) icon to remove profiles
- **Quick Loading**: One-click configuration switching
- **Visual Indicators**: Active configuration highlighted

#### Save-New-Config Panel
- **Config Name Field**: Text input for user-defined configuration labels
- **Save Button**: Writes current settings to localStorage under specified name
- **Validation**: Prevents duplicate names and invalid characters
- **Confirmation**: Success/error feedback for save operations

#### Persistence System
- **Toggle States**: All switch positions saved automatically
- **Slider Values**: Numeric settings preserved across sessions  
- **Last-Used Config**: Automatically loads previous configuration on startup
- **Storage Method**: localStorage with JSON serialization
- **Backup/Restore**: Configuration export/import capabilities

### Configuration Schema
```javascript
{
  "configName": "string",
  "timestamp": "ISO date",
  "visuals": {
    "playerESP": {
      "enabled": boolean,
      "skeleton": boolean,
      "box": { "enabled": boolean, "type": "2D|3D" },
      "chams": boolean,
      "health": boolean,
      "names": boolean,
      "distance": boolean,
      "visibilityCheck": boolean,
      "spectatorList": boolean,
      "ignoreTeam": boolean
    },
    "gadgetESP": {
      "traps": boolean,
      "cameras": boolean,
      "drones": boolean,
      "destructibles": boolean,
      "breachingCharges": boolean,
      "icons": boolean,
      "names": boolean
    },
    "environment": {
      "objectives": boolean,
      "bombTimer": boolean
    }
  },
  "performance": {
    "fpsLimit": number, // 30-144
    "espDistance": number // 10-100
  }
}
```

---

## 🔧 Development Notes

### Key Classes & Components
- **AccessApp**: Main authentication and license validation
- **SmoothCursor**: Optimized cursor animation system  
- **ColorPicker**: Custom color selection interface
- **ConfigManager**: Configuration persistence and management

### State Management
- **Master Toggle Logic**: Hierarchical enable/disable with state memory
- **Theme Persistence**: Dark/light mode preferences
- **Session Management**: Authentication state tracking

### Performance Considerations
- **Lazy Loading**: Components loaded on demand
- **Code Splitting**: Separate bundles for different sections
- **Asset Caching**: Immutable file naming for optimal caching
- **Memory Cleanup**: Proper event listener and timer cleanup

### Security Features
- **License Validation**: Server-side verification system
- **Session Timeout**: Automatic logout for inactive users
- **Risk Labeling**: Clear indication of feature risk levels

---

## 🚀 Getting Started

1. **Authentication**: Enter valid license code in main interface
2. **Navigation**: Access settings through authenticated menu system
3. **Configuration**: Use the Config panel to save/load different setups
4. **Customization**: Adjust Visuals and Performance settings as needed

## 📝 Notes for AI Analysis

- **File Sizes**: Menu/index.html is significantly large (~92KB) due to comprehensive feature set
- **Build System**: Uses SvelteKit with Vite for modern development workflow  
- **Styling**: Tailwind CSS with extensive custom CSS for specialized components
- **Browser Compatibility**: Modern browsers with ES6+ support required
- **Storage**: Relies on localStorage for all persistence (no server-side storage)

This codebase represents a professional-grade application with sophisticated UI/UX patterns, performance optimizations, and comprehensive feature management suitable for advanced users requiring detailed configuration control.
